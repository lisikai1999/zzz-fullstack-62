import re
from dataclasses import dataclass
from typing import List


@dataclass
class ScanRule:
    name: str
    pattern: re.Pattern
    severity: str
    description: str


SCAN_RULES: List[ScanRule] = [
    ScanRule(
        name="password_in_url",
        pattern=re.compile(rb'(?i)(password|passwd|pwd)\s*[=:]\s*(\S+)'),
        severity="high",
        description="Password transmitted in plaintext",
    ),
    ScanRule(
        name="bearer_token",
        pattern=re.compile(rb'Bearer\s+([A-Za-z0-9\-._~+/]+=*)'),
        severity="high",
        description="Bearer authentication token exposed",
    ),
    ScanRule(
        name="api_key",
        pattern=re.compile(rb'(?i)(api[_\-]?key|apikey)\s*[=:]\s*([A-Za-z0-9]{16,})'),
        severity="high",
        description="API key exposed in plaintext",
    ),
    ScanRule(
        name="authorization_basic",
        pattern=re.compile(rb'(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/]+=*)'),
        severity="high",
        description="Basic authentication credentials exposed",
    ),
    ScanRule(
        name="chinese_id_card",
        pattern=re.compile(rb'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'),
        severity="high",
        description="Chinese national ID card number detected",
    ),
    ScanRule(
        name="aws_access_key",
        pattern=re.compile(rb'AKIA[0-9A-Z]{16}'),
        severity="high",
        description="AWS access key ID detected",
    ),
    ScanRule(
        name="private_key",
        pattern=re.compile(rb'-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----'),
        severity="critical",
        description="Private key detected in traffic",
    ),
    ScanRule(
        name="credit_card_visa",
        pattern=re.compile(rb'\b4[0-9]{12}(?:[0-9]{3})?\b'),
        severity="high",
        description="Possible Visa credit card number",
    ),
    ScanRule(
        name="credit_card_mastercard",
        pattern=re.compile(rb'\b5[1-5][0-9]{14}\b'),
        severity="high",
        description="Possible Mastercard credit card number",
    ),
    ScanRule(
        name="email_address",
        pattern=re.compile(rb'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
        severity="medium",
        description="Email address detected in traffic",
    ),
    ScanRule(
        name="phone_number_cn",
        pattern=re.compile(rb'\b1[3-9]\d{9}\b'),
        severity="medium",
        description="Chinese mobile phone number detected",
    ),
    ScanRule(
        name="jwt_token",
        pattern=re.compile(rb'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        severity="high",
        description="JWT token detected in traffic",
    ),
    ScanRule(
        name="secret_in_header",
        pattern=re.compile(rb'(?i)(x-api-key|x-secret|x-token|x-auth)\s*:\s*(\S+)'),
        severity="high",
        description="Secret value in custom header",
    ),
    ScanRule(
        name="cookie_session",
        pattern=re.compile(rb'(?i)(?:session_?id|sess_?token|auth_?token)\s*=\s*([A-Za-z0-9+/=\-_.]{16,})'),
        severity="medium",
        description="Session token in cookie or parameter",
    ),
]
