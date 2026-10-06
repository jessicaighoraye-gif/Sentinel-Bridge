from .base_detector import BaseDetector
from .data_protection.encryption_at_rest_detector import EncryptionAtRestDetector
from .data_protection.encryption_in_transit_detector import EncryptionInTransitDetector
from .endpoint.endpoint_protection_detector import EndpointProtectionDetector
from .endpoint.vulnerable_software_detector import VulnerableSoftwareDetector
from .exposure.cloud_storage_exposure_detector import CloudStorageExposureDetector
from .exposure.remote_access_detector import RemoteAccessDetector
from .identity.excessive_privilege_detector import ExcessivePrivilegeDetector
from .identity.inactive_account_detector import InactiveAccountDetector
from .identity.mfa_detector import MfaDetector
from .identity.password_policy_detector import PasswordPolicyDetector
from .resilience.backup_recovery_detector import BackupRecoveryDetector
from .resilience.logging_monitoring_detector import LoggingMonitoringDetector

# Control order: IAM, DATA, END, LOG, CLD, BCP, NET
ALL_DETECTOR_CLASSES = [
    MfaDetector, ExcessivePrivilegeDetector, InactiveAccountDetector, PasswordPolicyDetector,
    EncryptionAtRestDetector, EncryptionInTransitDetector, VulnerableSoftwareDetector, EndpointProtectionDetector,
    LoggingMonitoringDetector, CloudStorageExposureDetector, BackupRecoveryDetector, RemoteAccessDetector,
]
