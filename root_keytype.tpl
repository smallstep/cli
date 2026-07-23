{
    "subject": {{ toJson .Subject }},
    "issuer": {{ toJson .Subject }},
    "keyUsage": ["certSign", "crlSign"],
    "basicConstraints": {
        "isCA": true,
        "maxPathLen": 1
    },
    "publicKeyTypeAlgorithm": "ed25519"
}
