import socket
import socks
import time

def test_udp_proxy(retry_count=3):
    """测试 UDP 代理，支持重试"""

    for attempt in range(retry_count):
        s = None
        try:
            print(f"\n[尝试 {attempt + 1}/{retry_count}] 开始测试...")
            start_time = time.time()

            # 1. 初始化 socksocket
            s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)

            # 2. 配置 SOCKS5 代理
            s.set_proxy(socks.SOCKS5, "127.0.0.1", 1080)

            # 测试目标：DNS 查询 google.com
            addr = ("8.8.8.8", 53)
            data = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"

            # 连接
            connect_start = time.time()
            s.connect(addr)
            print(f"  - 连接耗时: {time.time() - connect_start:.2f}秒")

            # 发送数据
            send_start = time.time()
            s.send(data)
            print(f"  - 发送耗时: {time.time() - send_start:.2f}秒")

            # 接收响应（15秒超时）
            s.settimeout(15)
            recv_start = time.time()
            response = s.recv(1024)
            recv_time = time.time() - recv_start
            print(f"  - 接收耗时: {recv_time:.2f}秒")

            total_time = time.time() - start_time
            print(f"\n✅ UDP 代理测试成功！")
            print(f"   总耗时: {total_time:.2f}秒")
            print(f"   响应长度: {len(response)} 字节")

            # 解析 DNS 响应，显示返回的 IP 地址
            if len(response) > 12:
                print(f"   DNS 响应: {response[:20].hex()}...")
                # DNS 响应包含答案数量
                answer_count = int.from_bytes(response[6:8], 'big')
                print(f"   答案数量: {answer_count}")

            return True

        except socket.timeout as e:
            elapsed = time.time() - start_time
            print(f"  ❌ 超时 (等待 {elapsed:.1f}秒): {e}")
            if attempt < retry_count - 1:
                wait_time = (attempt + 1) * 2
                print(f"  等待 {wait_time} 秒后重试...")
                time.sleep(wait_time)
            else:
                print("\n💡 建议:")
                print("  1. 检查 Hysteria2 服务器是否在线: ping 155.248.218.187")
                print("  2. 检查服务器 UDP 中继是否启用")
                print("  3. 查看服务器日志是否有错误")

        except Exception as e:
            print(f"  ❌ 错误: {e}")

        finally:
            if s:
                s.close()

    print(f"\n❌ 测试失败，已重试 {retry_count} 次")
    return False

if __name__ == "__main__":
    print("=" * 50)
    print("SOCKS5 UDP 代理测试 (通过 Hysteria2)")
    print("=" * 50)

    # 预热连接（首次连接需要建立 QUIC，较慢）
    print("\n[预热] 首次建立连接可能较慢...")
    success = test_udp_proxy(retry_count=2)

    if success:
        print("\n" + "=" * 50)
        print("🎉 所有测试通过！")
        print("=" * 50)
