import subprocess
import logging
from dataclasses import dataclass
from typing import List, Dict, Tuple
from datetime import datetime

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
            
            # 파싱 시작 지점 찾기
            if "시작 포트    끝 포트" in line:
                start_parsing = True
                continue
            
            if start_parsing and line:
                # 구분선 건너뛰기
                if "----------" in line:
                    continue
                
                # 빈 줄이나 설명줄 건너뛰기
                if not line or "관리 포트" in line:
                    continue
                
                try:
                    parts = line.split()
                    if len(parts) >= 2:
                        start_port = int(parts[0])
                        end_port = int(parts[1])
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