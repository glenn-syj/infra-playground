from port_analyzer import WinNATAnalyzer
import docker
import asyncio
import logging
import socket
from datetime import datetime

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
    
    # Windows 예약 포트 범위 확인
    excluded_ranges = analyzer.get_excluded_port_ranges()
    if not excluded_ranges:
        logging.error("Failed to get excluded port ranges")
        return None
    
    # 예약된 포트 중 하나 선택 (관리 포트 제외)
    test_port = None
    for range in excluded_ranges:
        if not range.is_admin:
            test_port = range.start_port
            break
    
    if not test_port:
        logging.error("No suitable test port found")
        return None
    
    container_name = f"port_test_{test_port}"
    logging.info(f"Testing with excluded port: {test_port}")
    
    try:
        # 이미지 확인 및 pull
        try:
            logging.info("Checking nginx image...")
            docker_client.images.get('nginx')
        except docker.errors.ImageNotFound:
            logging.info("Pulling nginx image...")
            docker_client.images.pull('nginx')
        
        # 동일 이름의 기존 컨테이너 정리
        try:
            old_container = docker_client.containers.get(container_name)
            logging.info(f"Found existing container: {container_name}")
            old_container.stop()
            old_container.remove()
            logging.info("Removed existing container")
        except docker.errors.NotFound:
            logging.info("No existing container found")
        
        # 1. Docker 컨테이너 생성
        logging.info(f"Creating new container: {container_name}")
        container = docker_client.containers.create(
            'nginx',
            name=container_name,
            ports={f'{test_port}/tcp': test_port}
        )
        
        # 2. 컨테이너 시작
        logging.info("Starting container...")
        container.start()
        
        # 컨테이너 상태 확인
        container.reload()
        state = container.attrs['State']
        
        if state['Status'] != 'running':
            error_msg = state.get('Error', '')
            exit_code = state.get('ExitCode', -1)
            logging.error(f"Container failed to start. Status: {state['Status']}, Error: {error_msg}, Exit code: {exit_code}")
            
            # 상세 로그 확인
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
        
        # 2. 충돌 시나리오 실행
        logging.info(f"Creating conflicting socket on port {test_port}")
        conflict_socket = await create_conflicting_socket(test_port)
        
        # 잠시 대기하여 충돌 상태 관찰
        await asyncio.sleep(5)
        
        # 3. 테스트 후 예약 포트 범위 재확인
        final_ranges = analyzer.get_excluded_port_ranges()
        
        # 컨테이너 상태 확인
        container.reload()
        container_state = container.attrs['State']
        
        if conflict_socket:
            conflict_socket.close()
            
        return {
            'test_port': test_port,
            'initial_ranges': excluded_ranges,
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
                logging.info(f"Cleaning up container: {container_name}")
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