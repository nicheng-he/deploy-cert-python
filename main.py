import os
import shutil
import subprocess
import threading
import time
import argparse
import uuid
import logging

from flask import Flask, request, jsonify

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# 解析命令行参数
parser = argparse.ArgumentParser()
parser.add_argument(
    '--port',
    type=int,
    default=9527,
    help='应用运行端口 (默认值: 9527)'
)
parser.add_argument(
    '--token',
    type=str,
    default=str(uuid.uuid4()),
    help='身份验证令牌 (默认值: 随机UUID)'
)
parser.add_argument(
    '--log-level',
    type=str,
    default='INFO',
    choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    help='设置日志级别 (默认值: INFO)'
)
parser.add_argument(
    '--base-path',
    type=str,
    default='/data/ssl',
    help='上传的SSL证书的路径 (默认值: /data/ssl)'
)
parser.add_argument(
    '--script',
    type=str,
    help='指定部署后要执行的脚本路径或命令。例如: "/data/reload.sh" 或 "nginx -s reload"'
)
args = parser.parse_args()

# 配置日志记录
logging.basicConfig(
    level=getattr(logging, args.log_level.upper(), logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# 当前日志等级
current_log_level = logging.getLogger().getEffectiveLevel()
# 端口
global_prot = args.port
# 鉴权 token
global_token = args.token

# nginx 的配置文件都在此目录，加上域名作为不同域名的证书目录
# 如：/data/ssl/example.com/cert.pem
# 如：/data/ssl/example.com/cert.key
base_path = args.base_path
# 执行的脚本
script_path = args.script

app = Flask(__name__)
@app.route('/deploy-cert', methods=['POST'])
def deploy_cert():
    try:
        # 区分请求类型
        data = {}
        files = {}

        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
        elif request.content_type and 'multipart/form-data' in request.content_type:
            data = request.form
            files = request.files
        else:
            return jsonify({'error': 'Unsupported Content-Type'}), 400

        token = request.headers.get('token')
        if token != global_token:
            return jsonify({'error': 'Invalid token'}), 401


        ssl_certificate = ''
        ssl_certificate_key = ''

        # 获取证书文件
        if 'cert' in files:
            # 如果是上传的文件，读取文件内容
            cert_file = files['cert']
            ssl_certificate = cert_file.read().decode('utf-8')
        else:
            # 否则从 JSON 字符串获取
            ssl_certificate = data.get('cert', '')

        # 获取证书密钥
        if 'key' in files:
            key_file = files['key']
            ssl_certificate_key = key_file.read().decode('utf-8')
        else:
            ssl_certificate_key = data.get('key', '')

        # 检测是否有值，避免无效请求
        if not ssl_certificate or not ssl_certificate_key:
            return jsonify({'error': 'Missing required fields'}), 400

        if current_log_level <= logging.DEBUG:
            ssl_certificate_formatted = ssl_certificate.replace('\n', '\\n')
            logging.debug(f"ssl_certificate:{ssl_certificate_formatted}")
            ssl_certificate_key_formatted = ssl_certificate_key.replace('\n', '\\n')
            logging.debug(f"ssl_certificate_key:{ssl_certificate_key_formatted}")

        # 获取域名列表
        domains = get_ssl_certificate_domain(ssl_certificate)

        logging.info(f"domains:{domains}")

        # 遍历域名列表
        for domain in domains:
            # 将泛域名中的 *. 去掉
            if domain.startswith('*.'):
                domain = domain.replace('*.', '', 1)
            # 创建目录
            domain_dir = os.path.join(base_path, domain)
            if os.path.exists(domain_dir):
                shutil.rmtree(domain_dir)
            os.makedirs(domain_dir)

            # 生成证书文件
            cert_path = os.path.join(domain_dir, 'cert.pem')
            key_path = os.path.join(domain_dir, 'cert.key')

            with open(cert_path, 'w') as cert_file:
                cert_file.write(ssl_certificate)

            with open(key_path, 'w') as key_file:
                key_file.write(ssl_certificate_key)

            logging.info(f"{domain} ==> 证书创建成功")

        # 执行脚本
        threading.Thread(target=execute_shell).start()

        # 返回前端结果
        return jsonify({'result': 'ok'}), 200
    except Exception as e:
        logging.error(f"未知错误: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# 读取SSL证书域名
def get_ssl_certificate_domain(cert_pem):
    cert_pem_bytes = cert_pem.encode('utf-8')
    # 加载证书
    cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
    # 获取域名信息
    domains = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        domains = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        # 如果没有找到 SubjectAlternativeName 扩展，尝试从 commonName 中获取域名
        subject = cert.subject
        for attr in subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                domains.append(attr.value)
    return domains

# 重启nginx
def execute_shell():
    """在延迟3秒后执行"""
    time.sleep(3)
    try:
        cmd = script_path if script_path else 'nginx -s reload'
        subprocess.run(
            ['bash', '-c', cmd],
            check=True,
            capture_output=True,
            text=True
        )
        logging.info('脚本执行完成。')
    except subprocess.CalledProcessError as e:
        logging.error(f"脚本执行失败: {e}")

if __name__ == '__main__':
    logging.info(f"证书部署目录 base_path: {base_path}")
    logging.info(f"鉴权 token: {global_token}")
    if script_path: logging.info(f"执行脚本: {script_path}")
    app.run(host='0.0.0.0', port=global_prot)
