{
  "subject": {
    "commonName": {{ toJson .Subject.CommonName }},
    "emailAddress": "adam@jefferson.me",
    "country": "Estonia"
  },
  "sans": {{ toJson .SANs }},
{{- if typeIs "*sa.PublicKey" .Insecure.CR.PublicKey }}
  "keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
  "keyUsage": ["digitalSignature"],
{{- end }}
  "extKeyUsage": ["serverAuth", "clientAuth"]
}
