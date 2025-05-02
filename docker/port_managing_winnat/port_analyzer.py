import subprocess
import logging
from dataclasses import dataclass
from typing import List, Dict, Tuple
from datetime import datetime
import time

@dataclass
class ExcludedPortRange:
    """Windows 예약 포트 범위 정보"""
    start_port: int
    end_port: int
    is_admin: bool = False

class WinNATAnalyzer:
    """Windows NAT 포트 분석기"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.netsh_path = r"C:\Windows\System32\netsh.exe"
    
    def get_excluded_port_ranges(self) -> List[ExcludedPortRange]:
        """Windows 예약 포트 범위 조회"""
        try:
            result = subprocess.run(
                [self.netsh_path, "interface", "ipv4", "show", "excludedportrange", "protocol=tcp"],
                capture_output=True,
                text=True,
                shell=True
            )
            return self._parse_excluded_ports(result.stdout)
        except Exception as e:
            self.logger.error(f"예약 포트 범위 조회 실패: {e}")
            return []

    def _parse_excluded_ports(self, output: str) -> List[ExcludedPortRange]:
        """예약 포트 범위 파싱"""
        ranges = []
        lines = output.strip().split('\n')
        start_parsing = False
        
        for line in lines:
            line = line.strip()
            
            # 파싱 시작 지점 찾기 (한글/영어 모두 대응)
            if "Start Port" in line or "시작 포트" in line:
                start_parsing = True
                continue
            
            if start_parsing and line:
                # 구분선 건너뛰기
                if "----------" in line:
                    continue
                
                # 빈 줄이나 설명줄 건너뛰기
                if not line or "Administered port" in line or "관리 포트" in line:
                    continue
                
                try:
                    # 숫자만 추출
                    numbers = [int(s) for s in line.split() if s.isdigit()]
                    if len(numbers) >= 2:
                        start_port = numbers[0]
                        end_port = numbers[1]
                        is_admin = '*' in line
                        ranges.append(ExcludedPortRange(
                            start_port=start_port,
                            end_port=end_port,
                            is_admin=is_admin
                        ))
                except Exception as e:
                    self.logger.warning(f"포트 범위 파싱 실패 (라인: {line}): {e}")
                    continue
        
        return ranges

    def is_port_available(self, port: int) -> bool:
        """특정 포트가 예약되지 않았는지 확인"""
        excluded_ranges = self.get_excluded_port_ranges()
        for range in excluded_ranges:
            if range.start_port <= port <= range.end_port:
                return False
        return True

    def kill_process_using_port(self, port: int) -> bool:
        """특정 포트를 사용하는 프로세스 종료"""
        try:
            # netstat으로 포트 사용 중인 프로세스 찾기
            result = subprocess.run(
                f"netstat -ano | findstr :{port}",
                capture_output=True,
                text=True,
                shell=True
            )
            
            if result.stdout:
                # PID 추출 (마지막 열)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        pid = line.strip().split()[-1]
                        self.logger.info(f"Found process {pid} using port {port}")
                        
                        # 프로세스 종료
                        kill_result = subprocess.run(
                            f"taskkill /PID {pid} /F",
                            capture_output=True,
                            text=True,
                            shell=True
                        )
                        
                        if kill_result.returncode == 0:
                            self.logger.info(f"Successfully terminated process {pid}")
                            return True
                        else:
                            self.logger.error(f"Failed to terminate process: {kill_result}")
            
            return False
        except Exception as e:
            self.logger.error(f"Error killing process: {e}")
            return False

    def exclude_port_from_winnat(self, port: int) -> bool:
        """특정 포트를 WinNAT에서 제외"""
        try:
            # 먼저 포트 사용 중인 프로세스 종료
            if self.kill_process_using_port(port):
                self.logger.info(f"Terminated process using port {port}")
            
            # 잠시 대기
            time.sleep(2)
            
            # 이제 포트 제외
            result = subprocess.run(
                [self.netsh_path, "interface", "ipv4", "delete", "excludedportrange", 
                 "protocol=tcp", f"startport={port}", "numberofports=1"],
                capture_output=True,
                text=True,
                shell=True
            )
            
            if result.returncode == 0:
                self.logger.info(f"Successfully excluded port {port} from WinNAT")
                return True
            else:
                self.logger.error(f"Failed to exclude port from WinNAT: {result}")
                return False
        except Exception as e:
            self.logger.error(f"Error excluding port from WinNAT: {e}")
            return False

    def add_port_to_winnat(self, port: int) -> bool:
        """포트를 WinNAT에 등록"""
        try:
            result = subprocess.run(
                [self.netsh_path, "interface", "ipv4", "add", "excludedportrange", 
                 "protocol=tcp", f"startport={port}", "numberofports=1"],
                capture_output=True,
                text=True,
                shell=True
            )
            if result.returncode == 0:
                self.logger.info(f"Successfully added port {port} to WinNAT")
                return True
            else:
                self.logger.error(f"Failed to add port to WinNAT: {result}")
                return False
        except Exception as e:
            self.logger.error(f"Error adding port to WinNAT: {e}")
            return False