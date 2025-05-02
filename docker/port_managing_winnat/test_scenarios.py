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
    
    # 테스트용 포트 설정 (8080)
    test_port = 8080
    logging.info(f"Testing with port: {test_port}")
    
    try:
        # 포트를 WinNAT에 등록
        logging.info(f"Adding port {test_port} to WinNAT")
        if not analyzer.add_port_to_winnat(test_port):
            logging.error("Failed to add port to WinNAT")
            return None
            
        logging.info("Port added to WinNAT successfully")
        await asyncio.sleep(2)  # 잠시 대기
        
        # 첫 번째 시도: 충돌 발생시키기
        logging.info("=== First attempt: Creating port conflict ===")
        
        # 소켓 생성으로 포트 선점
        conflict_socket = await create_conflicting_socket(test_port)
        if not conflict_socket:
            logging.error("Failed to create conflicting socket")
            return None
        
        logging.info(f"Created conflicting socket on port {test_port}")
        await asyncio.sleep(2)
        
        # WinNAT에서 해당 포트 제외
        logging.info(f"Excluding port {test_port} from WinNAT")
        if not analyzer.exclude_port_from_winnat(test_port):
            logging.error("Failed to exclude port from WinNAT")
            return None
            
        # 소켓 정리
        conflict_socket.close()
        logging.info("Closed conflicting socket")
        await asyncio.sleep(2)
        
        # 두 번째 시도: 컨테이너 실행
        logging.info("=== Second attempt: Running container ===")
        
        # 이미지 확인 및 pull
        try:
            logging.info("Checking nginx image...")
            docker_client.images.get('nginx')
        except docker.errors.ImageNotFound:
            logging.info("Pulling nginx image...")
            docker_client.images.pull('nginx')
        
        # 동일 이름의 기존 컨테이너 정리
        try:
            old_container = docker_client.containers.get(f"port_test_{test_port}")
            logging.info(f"Found existing container: port_test_{test_port}")
            old_container.stop()
            old_container.remove()
            logging.info("Removed existing container")
        except docker.errors.NotFound:
            logging.info("No existing container found")
        
        # Docker 컨테이너 생성 및 실행
        logging.info(f"Creating new container: port_test_{test_port}")
        container = docker_client.containers.create(
            'nginx',
            name=f"port_test_{test_port}",
            ports={f'{test_port}/tcp': test_port},
            detach=True
        )
        
        logging.info("Starting container...")
        container.start()
        
        # 컨테이너 상태 확인
        container.reload()
        state = container.attrs['State']
        
        if state['Status'] != 'running':
            error_msg = state.get('Error', '')
            exit_code = state.get('ExitCode', -1)
            logging.error(f"Container failed to start. Status: {state['Status']}, Error: {error_msg}, Exit code: {exit_code}")
            logs = container.logs(tail=50).decode('utf-8')
            logging.error(f"Container logs:\n{logs}")
            raise Exception(f"Container failed to start: {error_msg}")
            
        logging.info(f"Container started successfully: {container.id}")
        
        # 도커 로그 수집
        container_logs = []
        try:
            logs = container.logs(tail=10).decode('utf-8').split('\n')
            container_logs.extend(log.strip() for log in logs if log.strip())
            logging.info(f"Collected {len(container_logs)} log lines")
        except Exception as e:
            logging.error(f"Failed to collect logs: {e}")
        
        # 최종 상태 확인
        final_ranges = analyzer.get_excluded_port_ranges()
        container.reload()
        container_state = container.attrs['State']
        
        return {
            'test_port': test_port,
            'initial_ranges': analyzer.get_excluded_port_ranges(),
            'final_ranges': final_ranges,
            'container_logs': container_logs,
            'container_state': {
                'status': container_state['Status'],
                'running': container_state['Running'],
                'error': container_state.get('Error', ''),
                'exit_code': container_state.get('ExitCode', 0)
            }
        }
        
    except Exception as e:
        logging.error(f"Test failed: {str(e)}", exc_info=True)
        return None
    finally:
        # cleanup
        if container:
            try:
                logging.info(f"Cleaning up container: port_test_{test_port}")
                container.stop()
                container.remove()
                logging.info("Container cleanup completed")
            except docker.errors.APIError as e:
                logging.error(f"Cleanup failed: {e}")
                if hasattr(e, 'response'):
                    logging.error(f"API Response: {e.response.content.decode()}")

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