"""Framework-specific fix suggestions."""

from __future__ import annotations

from typing import Dict, List

from ..models import FixSuggestion, Finding


FIX_LIBRARY: Dict[str, Dict[str, str]] = {
    "MISSING_CSP": {
        "Express": "app.use((_, res, next) => { res.setHeader('Content-Security-Policy', "default-src 'self'"); next(); });",
        "Nginx": "add_header Content-Security-Policy ""default-src 'self'"" always;",
    },
    "CORS_MISCONFIG": {
        "Express": "const allowlist = ['https://app.example.com']; app.use(cors({ origin: (origin, cb) => cb(null, allowlist.includes(origin)), credentials: false }));",
        "Flask": "CORS(app, resources={r'*': {'origins': ['https://app.example.com']}}, supports_credentials=False)",
    },
}


def default_fix_suggestions(finding: Finding) -> List[FixSuggestion]:
    """Generate simple fix suggestions for known finding types."""
    fixes: List[FixSuggestion] = []
    options = FIX_LIBRARY.get(finding.type, {})
    for framework, snippet in options.items():
        fixes.append(
            FixSuggestion(
                finding_id=finding.id or 0,
                framework=framework,
                snippet=snippet,
                explanation="Customize the allowlist to match your production origins.",
            )
        )
    return fixes
