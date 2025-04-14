#!/usr/bin/env python
# mitmproxy_sqlmap_plugin.py

import os
import tempfile
import subprocess
import threading
import queue
import hashlib
import logging
import signal
import time

from mitmproxy import http
from cachetools import TTLCache
import colorama
from colorama import Fore, Style
from mitmproxy.http import Response  # 导入 Response 类
from mitmproxy import http
import logging

# 设置日志级别
logging.basicConfig(level=logging.CRITICAL)
# ==== 初始化 ====
colorama.init(autoreset=True)

# ==== 配置 ====
SQLMAP_PYTHON = r"C:\Users\HSD\AppData\Local\anaconda3\envs\python38\python"
SQLMAP_SCRIPT = r"sqlmap.py"
MAX_QUEUE_SIZE = 1000
REQUEST_CACHE_TTL_SECONDS = 3600

# ==== 日志设置 ====
log_path = os.path.join(tempfile.gettempdir(), "mitm_sqlmap.log")


class ColorFormatter(logging.Formatter):
    def format(self, record):
        level_color = {
            logging.INFO: Fore.GREEN,
            logging.WARNING: Fore.RED,
            logging.ERROR: Fore.RED,
            logging.CRITICAL: Fore.RED,
        }.get(record.levelno, "")
        msg = super().format(record)
        return f"{level_color}{msg}{Style.RESET_ALL}"

formatter = logging.Formatter('[%(asctime)s] %(message)s')
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColorFormatter('[%(asctime)s] %(message)s'))
file_handler = logging.FileHandler(log_path, encoding="utf-8")
file_handler.setFormatter(formatter)

logging.basicConfig(level=logging.INFO, handlers=[console_handler, file_handler])

# ==== 全局变量 ====
request_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
seen_requests = TTLCache(maxsize=10000, ttl=REQUEST_CACHE_TTL_SECONDS)
request_dir = os.path.join(tempfile.gettempdir(), "sqlmap_requests")
os.makedirs(request_dir, exist_ok=True)

sqlmap_processes = []
# 添加统计变量
stats = {
    "total_requests": 0,
    "completed_requests": 0,
    "skipped_requests": 0,
    "failed_requests": 0,
    "current_processing": 0,
    "start_time": time.time()
}

def print_stats():
    """打印当前统计信息"""
    current_time = time.time()
    elapsed_time = current_time - stats["start_time"]
    pending = stats["total_requests"] - stats["completed_requests"] - stats["skipped_requests"] - stats["failed_requests"]
    failed_ratio = (stats["failed_requests"] / stats["total_requests"] * 100) if stats["total_requests"] > 0 else 0
    
    print(f"\n{Fore.CYAN}[*] All pending requests have been scanned{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] scanned: {stats['completed_requests']}, pending: {pending}, requestSent: {stats['total_requests']}, latency: {elapsed_time:.2f}s, failedRatio: {failed_ratio:.2f}%{Style.RESET_ALL}")

def generate_request_hash(flow: http.HTTPFlow) -> str:
    raw = f"{flow.request.method} {flow.request.url}\n"
    for k, v in flow.request.headers.items():
        raw += f"{k}:{v}\n"
    raw += flow.request.content.decode("utf8", errors="replace")
    return hashlib.md5(raw.encode()).hexdigest()

def stop_all_sqlmap():
    logging.info("正在终止所有 sqlmap 子进程...")
    for proc in sqlmap_processes:
        try:
            proc.terminate()
            proc.wait(timeout=5)
            logging.info(f"已正常退出 sqlmap PID={proc.pid}")
        except subprocess.TimeoutExpired:
            proc.kill()
            logging.warning(f"强制杀死 sqlmap PID={proc.pid}")

class SqlmapWorker(threading.Thread):
    def run(self):
        while True:
            item = request_queue.get()
            if item is None:
                break
            tmp_file_path, scheme = item
            stats["current_processing"] += 1
            
            force_ssl_param = "--force-ssl" if scheme.lower() == "https" else ""
            sqlmap_cmd = [
                SQLMAP_PYTHON,
                SQLMAP_SCRIPT,
                "-r", tmp_file_path,
                "--threads", "10",
                "--level", "3",
                "--batch",
                "--flush-session",
                "-v 0",
                "--random-agent"
            ]
            if force_ssl_param:
                sqlmap_cmd.insert(6, force_ssl_param)

            logging.info(f"执行 sqlmap 命令: {' '.join(sqlmap_cmd)}")
            try:
                proc = subprocess.Popen(sqlmap_cmd)
                sqlmap_processes.append(proc)
                proc.wait()
                stats["completed_requests"] += 1
            except Exception as e:
                logging.error(f"sqlmap 执行失败: {e}")
                stats["failed_requests"] += 1
            finally:
                stats["current_processing"] -= 1
                request_queue.task_done()

worker_thread = SqlmapWorker(daemon=True)
worker_thread.start()

class SaveAndTrigger:
    def request(self, flow: http.HTTPFlow) -> None:
        # 这里根据需要进行处理，确保不会显示日志
        # 通过修改log的级别来避免显示这些信息
        logging.getLogger('mitmproxy').setLevel(logging.CRITICAL)

        stats["total_requests"] += 1
        request_hash = generate_request_hash(flow)

        if request_hash in seen_requests:
            logging.info(f"跳过重复请求: {flow.request.url}")
            stats["skipped_requests"] += 1
            flow.response = http.Response.make(
                200,
                b"Duplicate request skipped.",
                {"Content-Type": "text/plain"}
            )
            return
        else:
            seen_requests[request_hash] = True

        if request_queue.full():
            logging.warning("请求队列已满，拒绝新任务")
            flow.response = http.Response.make(
                503,
                b"Request queue full. Please try again later.",
                {"Content-Type": "text/plain"}
            )
            return

        request_text = f"{flow.request.method} {flow.request.url} HTTP/1.1\r\n"
        for name, value in flow.request.headers.items():
            request_text += f"{name}: {value}\r\n"
        request_text += "\r\n"
        request_text += flow.request.content.decode("utf8", errors="replace")

        tmp_file_path = os.path.join(request_dir, f"sqlmap_{request_hash}.txt")
        with open(tmp_file_path, "w", encoding="utf8") as f:
            f.write(request_text)

        request_queue.put((tmp_file_path, flow.request.scheme))
        logging.info(f"加入扫描队列: {flow.request.method} {flow.request.url} -> {tmp_file_path}")

        # 阻止请求继续转发到服务器
        flow.response = http.Response.make(
            200,
            b"Request intercepted and queued for sqlmap processing.",
            {"Content-Type": "text/plain"}
        )

    def done(self):
        logging.info("插件即将退出，开始清理资源")
        stop_all_sqlmap()
        request_queue.put(None)
        worker_thread.join(timeout=3)
        logging.info("后台线程已退出")
        print_stats()

addons = [
    SaveAndTrigger()
]
