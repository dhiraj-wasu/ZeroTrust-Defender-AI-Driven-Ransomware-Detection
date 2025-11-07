import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from models.schemas import ThreatAlert
from models.database import DatabaseManager

class ForensicCorrelator:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.logger = logging.getLogger(__name__)

    async def correlate_threat(self, current_alert: ThreatAlert) -> Dict[str, Any]:
        """Main forensic correlation engine"""
        self.logger.info(f"Starting forensic correlation for alert from {current_alert.agent_id}")
        
        # Get recent alerts for correlation
        recent_alerts = await self.db.get_recent_alerts(hours=24)
        
        # Filter and analyze related alerts
        relevant_alerts = self._find_relevant_alerts(current_alert, recent_alerts)
        
        # Build comprehensive correlation data
        correlation_data = {
            'related_alerts': relevant_alerts,
            'attack_timeline': self._build_attack_timeline(current_alert, relevant_alerts),
            'propagation_graph': self._build_propagation_graph(current_alert, relevant_alerts),
            'temporal_patterns': self._analyze_temporal_patterns(current_alert, relevant_alerts),
            'correlation_confidence': self._calculate_correlation_confidence(current_alert, relevant_alerts),
            'cross_agent_indicators': self._extract_cross_agent_indicators(current_alert, relevant_alerts)
        }
        
        return correlation_data

    def _find_relevant_alerts(self, current_alert: ThreatAlert, all_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find alerts relevant to the current threat"""
        relevant = []
        current_time = current_alert.timestamp
        
        for alert in all_alerts:
            # Skip the current alert itself
            if alert.get('incident_id') == getattr(current_alert, 'incident_id', None):
                continue
                
            alert_time = datetime.fromisoformat(alert['timestamp']) if isinstance(alert['timestamp'], str) else alert['timestamp']
            time_diff = (current_time - alert_time).total_seconds() / 60  # minutes
            
            # Include alerts from last 2 hours for correlation
            if time_diff <= 120:
                similarity_score = self._calculate_alert_similarity(current_alert, alert)
                
                if similarity_score > 0.3:  # Threshold for relevance
                    alert['similarity_score'] = similarity_score
                    relevant.append(alert)
        
        # Sort by similarity score (most similar first)
        relevant.sort(key=lambda x: x.get('similarity_score', 0), reverse=True)
        return relevant

    def _calculate_alert_similarity(self, alert1: ThreatAlert, alert2: Dict[str, Any]) -> float:
        """Calculate similarity score between two alerts"""
        score = 0.0
        
        # Malware process similarity
        malware1 = alert1.malware_process or ""
        malware2 = alert2.get('malware_process', "")
        if malware1 and malware2 and malware1.lower() == malware2.lower():
            score += 0.4
        
        # Network connection similarity
        net_similarity = self._compare_network_patterns(
            alert1.forensic_data.get('network_connections', []),
            alert2.get('forensic_data', {}).get('network_connections', [])
        )
        score += net_similarity * 0.3
        
        # File pattern similarity
        file_similarity = self._compare_file_patterns(
            alert1.forensic_data.get('file_access_patterns', {}),
            alert2.get('forensic_data', {}).get('file_access_patterns', {})
        )
        score += file_similarity * 0.3
        
        return min(1.0, score)

    def _compare_network_patterns(self, connections1: List[Dict], connections2: List[Dict]) -> float:
        """Compare network connection patterns"""
        if not connections1 or not connections2:
            return 0.0
            
        # Extract unique hosts and protocols
        hosts1 = set(conn.get('remote_host', '') for conn in connections1)
        hosts2 = set(conn.get('remote_host', '') for conn in connections2)
        protocols1 = set(conn.get('protocol', '') for conn in connections1) 
        protocols2 = set(conn.get('protocol', '') for conn in connections2)
        
        # Calculate similarity
        common_hosts = hosts1.intersection(hosts2)
        common_protocols = protocols1.intersection(protocols2)
        
        host_similarity = len(common_hosts) / max(len(hosts1), len(hosts2)) if hosts1 or hosts2 else 0
        protocol_similarity = len(common_protocols) / max(len(protocols1), len(protocols2)) if protocols1 or protocols2 else 0
        
        return (host_similarity + protocol_similarity) / 2

    def _compare_file_patterns(self, patterns1: Dict, patterns2: Dict) -> float:
        """Compare file access patterns"""
        if not patterns1 or not patterns2:
            return 0.0
            
        similarity = 0.0
        indicators = ['encryption_detected', 'ransom_note_found']
        
        for indicator in indicators:
            if (patterns1.get(indicator) and patterns2.get(indicator) and
                patterns1[indicator] == patterns2[indicator]):
                similarity += 0.5
        
        # Compare file extensions
        ext1 = set(patterns1.get('extensions_changed', []))
        ext2 = set(patterns2.get('extensions_changed', []))
        if ext1 and ext2:
            ext_similarity = len(ext1.intersection(ext2)) / max(len(ext1), len(ext2))
            similarity += ext_similarity * 0.5
            
        return min(1.0, similarity)

    def _build_attack_timeline(self, current_alert: ThreatAlert, related_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build chronological attack timeline"""
        timeline = []
        
        # Add current alert as main event
        timeline.append({
            'timestamp': current_alert.timestamp.isoformat(),
            'agent': current_alert.agent_id,
            'event_type': 'PRIMARY_DETECTION',
            'severity': current_alert.threat_level.value,
            'description': f"Malware '{current_alert.malware_process}' detected with {current_alert.detection_confidence} confidence",
            'forensic_evidence': {
                'files_modified': current_alert.forensic_data.get('file_access_patterns', {}).get('files_modified', 0),
                'network_connections': len(current_alert.forensic_data.get('network_connections', [])),
                'encryption_detected': current_alert.forensic_data.get('file_access_patterns', {}).get('encryption_detected', False)
            }
        })
        
        # Add related events
        for alert in related_alerts:
            timeline.append({
                'timestamp': alert['timestamp'],
                'agent': alert['agent_id'],
                'event_type': 'RELATED_ACTIVITY',
                'severity': alert['threat_level'],
                'description': f"Suspicious activity: {alert.get('malware_process', 'unknown process')}",
                'similarity_score': alert.get('similarity_score', 0),
                'relationship': self._determine_relationship(current_alert, alert)
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline

    def _determine_relationship(self, current_alert: ThreatAlert, related_alert: Dict[str, Any]) -> str:
        """Determine relationship between alerts"""
        similarity = related_alert.get('similarity_score', 0)
        
        if similarity > 0.7:
            return "DIRECTLY_RELATED"
        elif similarity > 0.4:
            return "LIKELY_RELATED" 
        else:
            return "POSSIBLY_RELATED"

    def _build_propagation_graph(self, current_alert: ThreatAlert, related_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build attack propagation graph"""
        graph = {
            'patient_zero': current_alert.agent_id,
            'infected_nodes': [current_alert.agent_id],
            'exposed_nodes': [],
            'contained_nodes': [],
            'propagation_paths': [],
            'attack_vector': self._identify_attack_vector(current_alert)
        }
        
        # Analyze network connections for propagation attempts
        network_connections = current_alert.forensic_data.get('network_connections', [])
        for conn in network_connections:
            if conn.get('direction') == 'outbound':
                graph['propagation_paths'].append({
                    'source': current_alert.agent_id,
                    'target': conn.get('remote_host'),
                    'protocol': conn.get('protocol'),
                    'port': conn.get('port'),
                    'timestamp': current_alert.timestamp.isoformat()
                })
                graph['exposed_nodes'].append(conn.get('remote_host'))
        
        # Add related alerts to graph
        for alert in related_alerts:
            if alert['agent_id'] not in graph['infected_nodes']:
                graph['exposed_nodes'].append(alert['agent_id'])
        
        # Remove duplicates
        graph['exposed_nodes'] = list(set(graph['exposed_nodes']))
        
        return graph

    def _identify_attack_vector(self, alert: ThreatAlert) -> str:
        """Identify primary attack vector"""
        network_connections = alert.forensic_data.get('network_connections', [])
        file_patterns = alert.forensic_data.get('file_access_patterns', {})
        
        if file_patterns.get('encryption_detected'):
            return "FILE_ENCRYPTION"
        elif any('SMB' in conn.get('protocol', '') for conn in network_connections):
            return "NETWORK_SHARING"
        elif any('RDP' in conn.get('protocol', '') for conn in network_connections):
            return "REMOTE_ACCESS"
        else:
            return "UNKNOWN_VECTOR"

    def _analyze_temporal_patterns(self, current_alert: ThreatAlert, related_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal patterns in the attack"""
        if not related_alerts:
            return {'pattern': 'ISOLATED_INCIDENT', 'confidence': 0.9}
        
        timestamps = [current_alert.timestamp] + [
            datetime.fromisoformat(alert['timestamp']) if isinstance(alert['timestamp'], str) else alert['timestamp']
            for alert in related_alerts
        ]
        
        timestamps.sort()
        time_diffs = []
        
        for i in range(1, len(timestamps)):
            diff = (timestamps[i] - timestamps[i-1]).total_seconds() / 60  # minutes
            time_diffs.append(diff)
        
        if not time_diffs:
            return {'pattern': 'SINGLE_EVENT', 'confidence': 0.8}
        
        avg_diff = sum(time_diffs) / len(time_diffs)
        
        if avg_diff < 5:  # Events within 5 minutes
            pattern = "RAPID_BURST"
            confidence = 0.85
        elif avg_diff < 30:  # Events within 30 minutes  
            pattern = "COORDINATED_ATTACK"
            confidence = 0.75
        else:
            pattern = "LOW_FREQUENCY"
            confidence = 0.6
            
        return {
            'pattern': pattern,
            'confidence': confidence,
            'average_time_between_events_minutes': avg_diff,
            'total_time_span_minutes': (timestamps[-1] - timestamps[0]).total_seconds() / 60
        }

    def _calculate_correlation_confidence(self, current_alert: ThreatAlert, related_alerts: List[Dict[str, Any]]) -> float:
        """Calculate overall correlation confidence"""
        if not related_alerts:
            return 0.3  # Low confidence for isolated alerts
            
        # Base confidence on number of related alerts
        base_confidence = min(0.7, len(related_alerts) * 0.1)
        
        # Adjust based on similarity scores
        avg_similarity = sum(alert.get('similarity_score', 0) for alert in related_alerts) / len(related_alerts)
        similarity_boost = avg_similarity * 0.3
        
        return min(1.0, base_confidence + similarity_boost)

    def _extract_cross_agent_indicators(self, current_alert: ThreatAlert, related_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract indicators of compromise across multiple agents"""
        indicators = []
        
        # Collect unique malware processes
        malware_processes = set()
        if current_alert.malware_process:
            malware_processes.add(current_alert.malware_process)
        malware_processes.update(alert.get('malware_process') for alert in related_alerts if alert.get('malware_process'))
        
        for malware in malware_processes:
            indicators.append({
                'type': 'MALWARE_PROCESS',
                'value': malware,
                'confidence': 0.8,
                'sources': [current_alert.agent_id] + [a['agent_id'] for a in related_alerts if a.get('malware_process') == malware]
            })
        
        # Collect network indicators
        all_connections = current_alert.forensic_data.get('network_connections', [])
        for alert in related_alerts:
            all_connections.extend(alert.get('forensic_data', {}).get('network_connections', []))
            
        suspicious_ports = {445, 3389, 22, 23}  # SMB, RDP, SSH, Telnet
        for conn in all_connections:
            if conn.get('port') in suspicious_ports and conn.get('direction') == 'outbound':
                indicators.append({
                    'type': 'SUSPICIOUS_CONNECTION',
                    'value': f"{conn.get('protocol')}://{conn.get('remote_host')}:{conn.get('port')}",
                    'confidence': 0.7,
                    'sources': [current_alert.agent_id]  # Simplified for demo
                })
        
        return indicators