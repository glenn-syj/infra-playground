from port_analyzer import WinNATAnalyzer
import docker
import asyncio
import logging
import socket
from datetime import datetime
import subprocess

async def create_conflicting_socket(port: int):
    """포트 충돌을 일으키기 위한 소켓 생성"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        sock.listen(1)
        return sock
    except Exception as e:
        logging.error(f"Socket creation failed: {e}")
        return None

async def run_conflict_test():
    analyzer = WinNATAnalyzer()
    docker_client = docker.from_env()
    container = None
    
    # 1. 현재 WinNAT 상태 확인하여 테스트할 포트 선택
    logging.info("\n=== Checking WinNAT State ===")
    current_ranges = analyzer.get_excluded_port_ranges()
    test_port = None
    
    for range in current_ranges:
        if not range.is_admin:  # 관리자 포트가 아닌 것 중에서 선택
            test_port = range.start_port
            logging.info(f"Selected existing WinNAT port {test_port} for testing")
            break
    
    if not test_port:
        logging.error("No suitable port found in WinNAT")
        return None
    
    try:
        # 2. Docker 컨테이너로 충돌 발생시키기
        logging.info("\n=== Testing Docker Container Creation ===")
        logging.info(f"Creating container with port mapping: host {test_port} -> container 80")
        
        try:
            container = docker_client.containers.create(
                'nginx',
                name=f"port_test_{test_port}",
                ports={
                    '80/tcp': {
                        'HostIp': '0.0.0.0',
                        'HostPort': str(test_port)
                    }
                },
                detach=True
            )
            
            logging.info("\nStarting container...")
            try:
                container.start()
                logging.error(f"Container started unexpectedly - port {test_port} should be reserved by WinNAT!")
                
                # 포트 바인딩 상태 확인
                container.reload()
                port_bindings = container.attrs['NetworkSettings']['Ports']
                logging.info(f"\nActual port bindings: {port_bindings}")
                
            except docker.errors.APIError as e:
                logging.info("Container failed to start as expected (port conflict)")
                logging.info(f"Error: {str(e)}")
            
        except Exception as e:
            logging.error(f"Error during container operation: {e}")
            
        finally:
            # 컨테이너 정리
            if container:
                try:
                    container.remove(force=True)
                    logging.info("Container cleaned up")
                except:
                    pass
                    
    except Exception as e:
        logging.error(f"Test failed: {e}")

async def main():
    """테스트 실행 및 결과 출력"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    result = await run_conflict_test()
    if result:
        print("\n=== Windows Port Conflict Test Results ===")
        print(f"Test port: {result['test_port']}")
        
        print("\nInitial excluded port ranges:")
        for range in result['initial_ranges']:
            admin_mark = "*" if range.is_admin else " "
            print(f"- {range.start_port}-{range.end_port} {admin_mark}")
        
        print("\nFinal excluded port ranges:")
        for range in result['final_ranges']:
            admin_mark = "*" if range.is_admin else " "
            print(f"- {range.start_port}-{range.end_port} {admin_mark}")
            
        print("\nContainer State:")
        state = result['container_state']
        print(f"Status: {state['status']}")
        print(f"Running: {state['running']}")
        if state['error']:
            print(f"Error: {state['error']}")
        print(f"Exit Code: {state['exit_code']}")
        
        print("\nContainer Logs:")
        for log in result['container_logs']:
            print(f"- {log}")

if __name__ == "__main__":
    asyncio.run(main())