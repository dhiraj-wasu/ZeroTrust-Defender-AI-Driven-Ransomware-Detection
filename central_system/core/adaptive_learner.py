import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from models.database import DatabaseManager

class AdaptiveLearner:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.logger = logging.getLogger(__name__)
        self.knowledge_base = self._initialize_knowledge_base()
        self.performance_metrics = {
            'false_positives': 0,
            'true_positives': 0,
            'response_times': [],
            'containment_success_rate': 0.0
        }

    def _initialize_knowledge_base(self) -> Dict[str, Any]:
        """Initialize the system knowledge base"""
        return {
            'threat_signatures': {
                'malicious_processes': {},
                'suspicious_patterns': {},
                'network_indicators': {},
                'behavioral_anomalies': {}
            },
            'response_playbooks': {
                'ransomware': self._get_ransomware_playbook(),
                'trojan': self._get_trojan_playbook(),
                'worm': self._get_worm_playbook(),
                'miner': self._get_miner_playbook()
            },
            'optimization_rules': {
                'threshold_adjustments': {},
                'pattern_weights': {},
                'response_priorities': {}
            }
        }

    def _get_ransomware_playbook(self) -> Dict[str, Any]:
        """Get ransomware response playbook"""
        return {
            'immediate_actions': [
                'isolate_network',
                'kill_malicious_process',
                'lock_file_system',
                'trigger_emergency_backup'
            ],
            'containment_actions': [
                'block_smb_sharing',
                'disable_remote_services',
                'enable_file_protection',
                'alert_security_team'
            ],
            'recovery_actions': [
                'restore_from_backup',
                'scan_for_persistence',
                'validate_system_integrity',
                'update_security_policies'
            ],
            'prevention_enhancements': [
                'enhance_file_monitoring',
                'strict_process_whitelisting',
                'network_segmentation',
                'backup_verification'
            ]
        }

    def _get_trojan_playbook(self) -> Dict[str, Any]:
        """Get trojan response playbook"""
        return {
            'immediate_actions': [
                'isolate_system',
                'terminate_suspicious_processes',
                'block_outbound_connections',
                'collect_forensic_data'
            ],
            'containment_actions': [
                'enable_process_monitoring',
                'scan_for_persistence',
                'check_network_connections',
                'analyze_startup_items'
            ],
            'recovery_actions': [
                'remove_malicious_files',
                'clean_registry_entries',
                'update_security_software',
                'system_integrity_check'
            ],
            'prevention_enhancements': [
                'enhance_execution_control',
                'application_whitelisting',
                'network_traffic_analysis',
                'user_behavior_monitoring'
            ]
        }

    def _get_worm_playbook(self) -> Dict[str, Any]:
        """Get worm response playbook"""
        return {
            'immediate_actions': [
                'network_wide_alert',
                'block_lateral_movement',
                'isolate_infected_segments',
                'enable_aggressive_monitoring'
            ],
            'containment_actions': [
                'patch_vulnerabilities',
                'update_security_rules',
                'monitor_network_traffic',
                'scan_all_systems'
            ],
            'recovery_actions': [
                'clean_infected_systems',
                'validate_network_security',
                'update_access_controls',
                'security_policy_review'
            ],
            'prevention_enhancements': [
                'vulnerability_management',
                'network_segmentation',
                'intrusion_detection_rules',
                'regular_security_assessments'
            ]
        }

    def _get_miner_playbook(self) -> Dict[str, Any]:
        """Get cryptominer response playbook"""
        return {
            'immediate_actions': [
                'kill_mining_processes',
                'block_mining_pool_ips',
                'reduce_system_load',
                'analyze_resource_usage'
            ],
            'containment_actions': [
                'monitor_cpu_usage',
                'block_suspicious_ports',
                'scan_for_mining_software',
                'check_system_performance'
            ],
            'recovery_actions': [
                'remove_mining_software',
                'clean_system_files',
                'optimize_performance',
                'update_resource_monitoring'
            ],
            'prevention_enhancements': [
                'resource_usage_monitoring',
                'network_traffic_analysis',
                'process_behavior_analysis',
                'system_performance_baselines'
            ]
        }

    async def learn_from_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Learn from incident and update knowledge base"""
        self.logger.info(f"Learning from incident: {incident_data.get('incident_id')}")
        
        updates = {
            'threat_signatures': await self._update_threat_signatures(incident_data),
            'response_playbooks': await self._optimize_response_playbooks(incident_data),
            'optimization_rules': await self._update_optimization_rules(incident_data)
        }
        
        # Update performance metrics
        await self._update_performance_metrics(incident_data)
        
        # Apply updates to knowledge base
        self.knowledge_base = self._merge_knowledge_updates(updates)
        
        return {
            'updates_applied': len(updates['threat_signatures']) + len(updates['response_playbooks']) + len(updates['optimization_rules']),
            'performance_metrics': self.performance_metrics,
            'timestamp': datetime.now().isoformat()
        }

    async def _update_threat_signatures(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update threat signatures based on incident"""
        updates = {}
        alert_data = incident_data.get('alert', {})
        forensic_data = alert_data.get('forensic_data', {})
        
        # Update malicious processes
        malware_process = alert_data.get('malware_process')
        if malware_process:
            process_updates = self._update_malicious_process(malware_process, incident_data)
            updates['malicious_processes'] = process_updates
        
        # Update suspicious patterns
        pattern_updates = self._update_suspicious_patterns(forensic_data, incident_data)
        updates['suspicious_patterns'] = pattern_updates
        
        # Update network indicators
        network_updates = self._update_network_indicators(forensic_data, incident_data)
        updates['network_indicators'] = network_updates
        
        return updates

    def _update_malicious_process(self, process_name: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update malicious process signatures"""
        confidence = incident_data.get('llm_analysis', {}).get('confidence_score', 0.5)
        threat_level = incident_data.get('alert', {}).get('threat_level', 'medium')
        
        return {
            process_name: {
                'first_seen': datetime.now().isoformat(),
                'confidence': confidence,
                'threat_level': threat_level,
                'incident_count': 1,
                'last_updated': datetime.now().isoformat()
            }
        }

    def _update_suspicious_patterns(self, forensic_data: Dict[str, Any], incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update suspicious behavior patterns"""
        patterns = {}
        file_patterns = forensic_data.get('file_access_patterns', {})
        
        if file_patterns.get('encryption_detected'):
            patterns['rapid_file_encryption'] = {
                'description': 'Rapid file encryption pattern detected',
                'confidence': 0.9,
                'response_priority': 'HIGH'
            }
        
        if file_patterns.get('ransom_note_found'):
            patterns['ransomware_indicators'] = {
                'description': 'Ransom note and encryption patterns',
                'confidence': 0.95,
                'response_priority': 'CRITICAL'
            }
        
        return patterns

    def _update_network_indicators(self, forensic_data: Dict[str, Any], incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update network-based indicators"""
        indicators = {}
        network_connections = forensic_data.get('network_connections', [])
        
        for conn in network_connections:
            if conn.get('protocol') == 'SMB' and conn.get('direction') == 'outbound':
                indicators['suspicious_smb_lateral'] = {
                    'description': 'SMB lateral movement attempts',
                    'confidence': 0.8,
                    'response_priority': 'HIGH'
                }
        
        return indicators

    async def _optimize_response_playbooks(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize response playbooks based on incident outcomes"""
        optimizations = {}
        attack_class = incident_data.get('llm_analysis', {}).get('attack_classification', '')
        response_effectiveness = self._assess_response_effectiveness(incident_data)
        
        if 'RANSOMWARE' in attack_class.upper():
            optimizations['ransomware'] = self._optimize_ransomware_playbook(incident_data, response_effectiveness)
        
        return optimizations

    def _assess_response_effectiveness(self, incident_data: Dict[str, Any]) -> float:
        """Assess how effective the response was"""
        # Simple effectiveness calculation based on containment
        risk_assessment = incident_data.get('risk_assessment', {})
        propagation_likelihood = risk_assessment.get('propagation_likelihood', 'LOW')
        
        effectiveness_scores = {
            'VERY_HIGH': 0.2,  # High propagation = less effective
            'HIGH': 0.4,
            'MEDIUM': 0.7,
            'LOW': 0.9
        }
        
        return effectiveness_scores.get(propagation_likelihood, 0.5)

    def _optimize_ransomware_playbook(self, incident_data: Dict[str, Any], effectiveness: float) -> Dict[str, Any]:
        """Optimize ransomware response playbook"""
        optimizations = {}
        
        if effectiveness < 0.7:
            # Need more aggressive containment
            optimizations['immediate_actions'] = ['enhanced_network_isolation', 'immediate_backup_trigger']
            optimizations['containment_actions'] = ['strict_file_system_lockdown', 'aggressive_process_termination']
        
        return optimizations

    async def _update_optimization_rules(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update optimization rules and thresholds"""
        rules = {}
        
        # Adjust detection thresholds based on false positives
        fp_rate = self.performance_metrics.get('false_positive_rate', 0)
        if fp_rate > 0.1:  # High false positive rate
            rules['threshold_adjustments'] = {
                'suspicion_threshold': 'increase_by_10_percent',
                'confidence_threshold': 'increase_by_5_percent'
            }
        
        return rules

    async def _update_performance_metrics(self, incident_data: Dict[str, Any]):
        """Update system performance metrics"""
        # Update response times
        response_time = self._calculate_response_time(incident_data)
        self.performance_metrics['response_times'].append(response_time)
        
        # Keep only last 100 response times
        if len(self.performance_metrics['response_times']) > 100:
            self.performance_metrics['response_times'] = self.performance_metrics['response_times'][-100:]
        
        # Update success rates
        if self._was_incident_contained(incident_data):
            self.performance_metrics['true_positives'] += 1
        else:
            self.performance_metrics['false_positives'] += 1
        
        # Calculate containment success rate
        total_incidents = self.performance_metrics['true_positives'] + self.performance_metrics['false_positives']
        if total_incidents > 0:
            self.performance_metrics['containment_success_rate'] = (
                self.performance_metrics['true_positives'] / total_incidents
            )

    def _calculate_response_time(self, incident_data: Dict[str, Any]) -> float:
        """Calculate response time for incident"""
        alert_time = incident_data.get('alert', {}).get('timestamp')
        if isinstance(alert_time, str):
            alert_time = datetime.fromisoformat(alert_time)
        
        response_time = incident_data.get('response_timestamp')
        if isinstance(response_time, str):
            response_time = datetime.fromisoformat(response_time)
        
        if alert_time and response_time:
            return (response_time - alert_time).total_seconds()
        return 0.0

    def _was_incident_contained(self, incident_data: Dict[str, Any]) -> bool:
        """Determine if incident was successfully contained"""
        risk_assessment = incident_data.get('risk_assessment', {})
        propagation_likelihood = risk_assessment.get('propagation_likelihood', 'LOW')
        
        return propagation_likelihood in ['LOW', 'MEDIUM']

    def _merge_knowledge_updates(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Merge updates into knowledge base"""
        merged_kb = self.knowledge_base.copy()
        
        for category, category_updates in updates.items():
            if category in merged_kb:
                for subcategory, sub_updates in category_updates.items():
                    if subcategory in merged_kb[category]:
                        merged_kb[category][subcategory].update(sub_updates)
                    else:
                        merged_kb[category][subcategory] = sub_updates
        
        return merged_kb

    async def get_optimized_response(self, threat_type: str, severity: str) -> List[str]:
        """Get optimized response actions for threat type"""
        playbook = self.knowledge_base['response_playbooks'].get(threat_type.lower(), {})
        
        if severity == 'CRITICAL':
            return playbook.get('immediate_actions', []) + playbook.get('containment_actions', [])
        elif severity == 'HIGH':
            return playbook.get('containment_actions', [])
        else:
            return playbook.get('recovery_actions', [])

    async def get_performance_report(self) -> Dict[str, Any]:
        """Get system performance report"""
        response_times = self.performance_metrics.get('response_times', [])
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            'performance_metrics': {
                'average_response_time_seconds': avg_response_time,
                'containment_success_rate': self.performance_metrics.get('containment_success_rate', 0),
                'false_positives': self.performance_metrics.get('false_positives', 0),
                'true_positives': self.performance_metrics.get('true_positives', 0),
                'total_incidents_learned': self.performance_metrics.get('true_positives', 0) + self.performance_metrics.get('false_positives', 0)
            },
            'knowledge_base_stats': {
                'threat_signatures': len(self.knowledge_base.get('threat_signatures', {})),
                'response_playbooks': len(self.knowledge_base.get('response_playbooks', {})),
                'optimization_rules': len(self.knowledge_base.get('optimization_rules', {}))
            },
            'last_updated': datetime.now().isoformat()
        }