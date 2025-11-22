import streamlit as st
import netmiko
import requests
import json
import sqlite3
import pandas as pd
import time
import traceback
from datetime import datetime, timezone 
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 1. 全局配置 ---
DB_FILE = "net_sentinel_final.db"
OLLAMA_BASE_URL = "http://localhost:11434"
AI_TIMEOUT = 300  # AI 推理超时时间（秒）

# --- 2. 数据库管理层 ---
class DBManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT, ip TEXT, username TEXT, password TEXT, port INTEGER DEFAULT 22,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inspection_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_devices INTEGER,
                risk_count INTEGER,
                avg_score INTEGER,
                model_used TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inspection_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER,
                device_name TEXT,
                device_ip TEXT,
                raw_log TEXT,
                ai_json TEXT,
                score INTEGER,
                status TEXT,
                FOREIGN KEY(task_id) REFERENCES inspection_tasks(id)
            )
        ''')
        self.conn.commit()

    def add_device(self, hostname, ip, username, password, port=22):
        self.conn.execute("INSERT INTO devices (hostname, ip, username, password, port) VALUES (?, ?, ?, ?, ?)",
                          (hostname, ip, username, password, port))
        self.conn.commit()

    def delete_device(self, dev_id):
        self.conn.execute("DELETE FROM devices WHERE id = ?", (dev_id,))
        self.conn.commit()

    def get_devices(self):
        df = pd.read_sql("SELECT * FROM devices", self.conn)
        return df.to_dict('records')

    # V8.0 核心修改：改为保存批处理报告结果
    def save_batch_inspection(self, device_results, ai_result, model_name):
        """保存批处理巡检结果（一个 AI 报告 + 多个设备原始日志）"""
        total = len(device_results)
        
        # 批处理模式下，分数和风险数主要用于占位
        successful_connections = [r for r in device_results if r['success']]
        avg_score = ai_result.get('score', 0)
        risk_count = 0 

        cursor = self.conn.cursor()
        # 1. 保存任务信息
        cursor.execute("INSERT INTO inspection_tasks (total_devices, risk_count, avg_score, model_used) VALUES (?, ?, ?, ?)",
                       (total, risk_count, avg_score, model_name))
        task_id = cursor.lastrowid

        # 2. 保存单一的 AI 完整报告（存入一个特殊的 details 条目）
        report_json_str = json.dumps(ai_result, ensure_ascii=False)
        cursor.execute('''
            INSERT INTO inspection_details (task_id, device_name, device_ip, raw_log, ai_json, score, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (task_id, "AI_FULL_REPORT", "0.0.0.0", "", report_json_str, avg_score, "COMPLETE_REPORT"))

        # 3. 保存单个设备的原始日志
        for res in device_results:
            dev = res['device']
            status = "Success" if res['success'] else "Connection Error"
            raw_log = res.get('raw_data', res.get('error', 'No Data'))
            
            cursor.execute('''
                INSERT INTO inspection_details (task_id, device_name, device_ip, raw_log, ai_json, score, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (task_id, dev['hostname'], dev['ip'], raw_log, "{}", 0, status))
        
        self.conn.commit()
        return task_id

    def get_history_tasks(self):
        return pd.read_sql("SELECT * FROM inspection_tasks ORDER BY id DESC", self.conn)

    def get_task_details(self, task_id):
        return pd.read_sql(f"SELECT * FROM inspection_details WHERE task_id = {task_id}", self.conn)

# --- 3. 业务逻辑层 (Netmiko + LLM) ---
class InspectorLogic:
    @staticmethod
    def get_ollama_models():
        try:
            res = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2)
            if res.status_code == 200:
                available_models = [m['name'] for m in res.json()['models']]
                target_models = ['deepseek', 'qwen', 'mistral', 'llama']
                return [m for m in available_models if any(t in m for t in target_models)]
        except:
            return []
        return []

    # 沿用 huawei_inspect_web.py 的指令集
    COMMANDS = [
        "display version",
        "display device",
        "display cpu-usage",
        "display memory-usage",
        "display interface brief",
        "display transceiver diagnosis interface",
        "display fan",
        "display power",
        "display temperature all",
        "display health",
        "display alarm active",
        "display logbuffer",
        "display trapbuffer",
        "display current-configuration | include sysname",
    ]

    @staticmethod
    def collect_data(device):
        """收集单个设备的原始日志"""
        log_text = f"=== Device: {device['hostname']} ({device['ip']}) ===\n"
        
        try:
            # 重新配置参数以使用更完整的指令集
            params = {
                'device_type': 'huawei',
                'host': device['ip'],
                'username': device['username'],
                'password': device['password'],
                'port': device['port'],
                'timeout': 30,
                'global_delay_factor': 2
            }
            with netmiko.ConnectHandler(**params) as conn:
                for cmd in InspectorLogic.COMMANDS:
                    output = conn.send_command(cmd)
                    log_text += f"\n[Command: {cmd}]\n{output}\n"
            return True, log_text
        except Exception as e:
            return False, f"SSH Connect Error: {str(e)}"

    # V8.1 核心修改：在 Prompt 中强制要求中文输出
    @staticmethod
    def analyze_log(raw_text_all, model_name):
        """AI 分析模块 - V8.1 核心：生成自由格式 Markdown 报告，并强制中文输出"""
        
        # 沿用 huawei_inspect_web.py 的 Prompt，并增加中文强制要求
        prompt = f"""
你是一名华为网络专家，对以下华为交换机巡检信息（可能是多台）进行全面智能分析。

要求（严格遵守）：
1. 先用一句话总结所有设备的整体健康状态
2. 然后分设备列出所有发现的异常/风险项（如果没有就写“未发现明显异常”）
3. 每项异常都要说明可能原因 + 建议处理措施
4. 最后给出整体优化建议（固件升级、配置优化、硬件建议等）
5. 输出必须是标准 Markdown，**全程使用中文（简体）**，语言通俗易懂，带表情符号更佳

巡检信息如下：
{raw_text_all}

请开始分析：
"""
        
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
        }

        try:
            res = requests.post(f"{OLLAMA_BASE_URL}/api/generate", json=payload, timeout=AI_TIMEOUT)
            
            if res.status_code == 200:
                response_text = res.json().get('response', '').strip()
                
                if not response_text:
                    return {"score": 0, "status": "Error", "summary": "AI 返回了空内容", "report_text": "AI返回了空报告。"}

                # 成功生成报告，设置一个成功的状态和分数（仅为占位）
                return {
                    "score": 100, 
                    "status": "Report Generated", 
                    "summary": "AI分析报告已生成 (Markdown格式)",
                    "report_text": response_text
                }
            else:
                return {"score": 0, "status": "API Error", "summary": f"Ollama API 报错: {res.status_code} - {res.text}", "report_text": f"API Error: {res.text}"}

        except requests.exceptions.ReadTimeout:
            return {"score": 0, "status": "Timeout", "summary": f"模型推理超时 (> {AI_TIMEOUT}s)", "report_text": "模型推理超时。"}
        except requests.exceptions.ConnectionError:
            return {"score": 0, "status": "Conn Error", "summary": "无法连接本地 Ollama 服务", "report_text": "无法连接本地 Ollama 服务。"}
        except Exception as e:
            return {"score": 0, "status": "Exception", "summary": f"Python执行未知异常: {str(e)}", "traceback": traceback.format_exc(), "report_text": f"Python执行未知异常: {str(e)}"}


# --- 4. 报告生成器 (V8.0 仅用于下载报告) ---
def generate_report_text(task_info, details_df):
    t = datetime.strptime(task_info['task_time'], "%Y-%m-%d %H:%M:%S")
    report = f"# 📜 网络设备智能巡检报告\n\n"
    
    report += f"**巡检时间**: {t} | **AI 模型**: {task_info['model_used']}\n"
    # 批处理模式下分数和风险数仅作参考
    report += f"**设备总数**: {task_info['total_devices']} 台 | **风险设备**: N/A | **平均健康分**: N/A\n\n---\n\n"

    # 1. 查找完整的 AI 报告
    ai_report_row = details_df[details_df['device_name'] == 'AI_FULL_REPORT']
    
    if not ai_report_row.empty:
        try:
            ai_data = json.loads(ai_report_row.iloc[0]['ai_json'])
            full_report_text = ai_data.get('report_text', 'AI 报告内容丢失。')
            
            report += "## 🤖 AI 智能分析结果\n\n"
            report += full_report_text
            report += "\n\n---\n\n"
        except:
            report += "## 🤖 AI 智能分析结果\n\n报告数据解析失败。\n\n---\n\n"

    # 2. 列出原始日志
    raw_logs_df = details_df[details_df['device_name'] != 'AI_FULL_REPORT']
    report += "# 📑 原始巡检日志列表 (设备维度)\n\n"
    for _, row in raw_logs_df.iterrows():
        status = row['status']
        icon = "✅" if status == "Success" else "❌"
        
        report += f"## {icon} {row['device_name']} ({row['device_ip']}) - Status: {status}\n"
        report += "### 原始日志内容\n"
        # 包含完整的原始日志用于下载报告
        report += f"```text\n{row['raw_log']}\n```\n\n"
        
    return report

# --- 5. Web UI 主程序 ---
def main():
    st.set_page_config(page_title="NetSentinel AI V8.1", page_icon="🛡️", layout="wide")
    db = DBManager()
    local_models = InspectorLogic.get_ollama_models()

    # --- 侧边栏导航 ---
    with st.sidebar:
        st.title("🛡️本地AI巡检系统 V8.1")
        
        if local_models:
            st.success("Ollama 在线 🟢")
            selected_model = st.selectbox("选择 AI 模型 (Markdown模式)", local_models, index=0, 
                                          help="当前版本为 Markdown 报告模式，不再强制 JSON")
        else:
            st.error("Ollama 离线 🔴")
            st.info("请在终端运行 'ollama serve' 或检查模型是否已下载")
            selected_model = None

        st.divider()
        page = st.radio("导航", ["🔍 智能巡检", "📜 历史档案", "⚙️ 设备管理"])

    # ================= 页面 1: 设备管理 =================
    if page == "⚙️ 设备管理":
        st.header("⚙️ 设备资产库")
        
        with st.expander("➕ 新增设备", expanded=True):
            with st.form("add_dev"):
                c1, c2 = st.columns(2)
                h = c1.text_input("Hostname", "SW1")
                i = c2.text_input("IP Address", "192.168.x.x")
                u = c1.text_input("Username", "admin")
                p = c2.text_input("Password", type="password")
                if st.form_submit_button("保存设备"):
                    if h and i and u and p: db.add_device(h, i, u, p); st.success("已添加!"); time.sleep(0.5); st.rerun()
                    else: st.warning("请填写完整信息")
        
        devices = db.get_devices()
        if devices:
            st.dataframe(pd.DataFrame(devices)[['id', 'hostname', 'ip', 'username']], hide_index=True, width='stretch')
            with st.form("del_dev"):
                d_id = st.selectbox("选择要移除的设备ID", [d['id'] for d in devices])
                if st.form_submit_button("🗑️ 删除选中"): db.delete_device(d_id); st.rerun()
        else:
            st.info("资产库为空。")

    # ================= 2: 开始巡检 (V8.0 批处理) =================
    elif page == "🔍 智能巡检":
        st.header("🌐 华为交换机智能巡检控制台")
        devices = db.get_devices()
        
        if not devices: st.warning("请先去“设备管理”添加设备！"); return
        if not selected_model: st.error("❌ 无法执行：Ollama 服务或指定模型未就绪。"); return

        st.metric("待巡检设备", f"{len(devices)} 台")
        
        if st.button("🚀 启动全网智能巡检", type="primary", width='stretch'):
            
            progress_bar = st.progress(0, text="正在初始化...")
            status_text = st.empty()
            device_results = []
            all_raw_data = ""
            
            # 1. 多线程采集数据
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_device = {executor.submit(InspectorLogic.collect_data, dev): dev for dev in devices}
                collected_count = 0
                
                status_text.text(f"开始采集 {len(devices)} 台设备数据...")

                for future in as_completed(future_to_device):
                    dev = future_to_device[future]
                    success, raw_data = future.result()
                    
                    collected_count += 1
                    status_text.text(f"[{collected_count}/{len(devices)}] 完成采集: {dev['hostname']}")
                    progress_bar.progress(collected_count / len(devices) * 0.5) # 进度条前一半用于采集

                    result = {
                        'device': dev,
                        'success': success,
                        'raw_data': raw_data if success else None,
                        'error': raw_data if not success else None
                    }
                    device_results.append(result)
                    
                    if success:
                         # 累加原始数据用于批处理分析
                         all_raw_data += f"\n\n--- Device: {dev['hostname']} ({dev['ip']}) ---\n\n{raw_data}"
            
            # 2. AI 批处理分析
            if all_raw_data.strip():
                status_text.text(f"开始调用 AI 模型 ({selected_model}) 进行批处理分析...")
                progress_bar.progress(0.5, text="开始 AI 分析...")
                
                ai_res = InspectorLogic.analyze_log(all_raw_data, selected_model) 
            else:
                ai_res = {"score": 0, "status": "Fail", "summary": "所有设备连接失败，无法生成报告", "report_text": "所有设备连接失败。"}

            # 3. 保存结果
            status_text.text("任务完成，正在保存记录...")
            progress_bar.progress(0.9, text="正在保存记录...")
            
            task_id = db.save_batch_inspection(device_results, ai_res, selected_model)
            
            progress_bar.progress(1.0, text="保存完毕")
            status_text.success(f"✅ 巡检结束！任务ID: {task_id}，请前往“历史档案”查看。")

    # ================= 3: 历史档案 (V8.0 展示) =================
    elif page == "📜 历史档案":
        st.header("📜 历史巡检档案")
        tasks = db.get_history_tasks()
        
        if tasks.empty: st.info("暂无历史记录。"); return

        c_list, c_detail = st.columns([1, 3])
        
        with c_list:
            st.subheader("任务列表")
            # st.caption("✅ **时间已修复**: 已转换为本地时区。")
            
            for _, row in tasks.iterrows():
                try:
                    dt_utc_naive = datetime.strptime(row['task_time'], "%Y-%m-%d %H:%M:%S")
                    dt_utc_aware = dt_utc_naive.replace(tzinfo=timezone.utc)
                    dt_local = dt_utc_aware.astimezone(None)
                    formatted_time = dt_local.strftime("%m-%d %H:%M")
                except Exception as e:
                    formatted_time = "时间错误"
                    
                # 批处理模式下显示设备总数
                label = f"📅 {formatted_time} | {row['total_devices']} 台"
                if st.button(label, key=row['id'], width='stretch'):
                    st.session_state['sel_task'] = row

        with c_detail:
            if 'sel_task' in st.session_state:
                task = st.session_state['sel_task']
                details = db.get_task_details(task['id'])
                
                st.subheader(f"详情 (ID: {task['id']}) - 模型: {task.get('model_used', 'N/A')}")
                
                # 下载按钮
                report_txt = generate_report_text(task, details)
                st.download_button("📥 下载本次巡检报告 (.md)", report_txt, f"report_{task['id']}.md", key="dl_task_report")
                
                st.divider()

                # V8.0 Display: 查找并显示完整的 AI 报告
                ai_report_row = details[details['device_name'] == 'AI_FULL_REPORT']
                
                if not ai_report_row.empty:
                    try:
                        ai_data = json.loads(ai_report_row.iloc[0]['ai_json'])
                        full_report_text = ai_data.get('report_text', 'AI 报告内容丢失。')
                        ai_status = ai_data.get('status', 'N/A')
                        
                        if ai_status not in ['Report Generated', 'COMPLETE_REPORT']:
                             st.error(f"❌ **AI 报告生成失败**: {ai_data.get('summary', '未知错误')}")
                             with st.popover("🕵️‍♀️ 调试: 查看 AI 原始返回内容"):
                                st.code(full_report_text, language='json')
                        else:
                            st.subheader("🤖 智能分析报告 (Markdown)")
                            st.markdown(full_report_text) # 显示完整的 Markdown 报告
                            st.divider()
                    except Exception as e:
                        st.error(f"AI 报告数据解析失败，可能报告内容已损坏。")
                
                # V8.0 Display: 列出原始日志供下载
                st.subheader("📑 设备原始日志")
                raw_logs_df = details[details['device_name'] != 'AI_FULL_REPORT']
                
                for _, row in raw_logs_df.iterrows():
                    status = row['status']
                    color = "red" if status != "Success" else "green"
                    
                    with st.expander(f"{row['device_name']} ({row['device_ip']}) - :{color}[{status}]"):
                        
                        col_dl1, col_dl2 = st.columns([1, 4])
                        
                        col_dl1.download_button(
                            "📥 下载原始日志",
                            row['raw_log'].encode('utf-8'),
                            file_name=f"log_{row['device_name']}_{task['id']}_{row['id']}.txt",
                            key=f"dl_log_{row['id']}"
                        )
                        
                        with st.popover("⚙️ 查看日志文本"):
                            # 仅显示前 3000 字符，防止 Streamlit 崩溃
                            display_log = row['raw_log'][:3000] + ("\n... [日志内容过多，请下载查看完整版]" if len(row['raw_log']) > 3000 else "")
                            st.code(display_log, language='text')

            else:
                st.info("👈 请在左侧点击一个任务以查看详情。")


if __name__ == "__main__":
    main()