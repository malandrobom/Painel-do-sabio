

from flask import Flask, request, jsonify, send_from_directory
import os
import re
import ipaddress
import requests

app = Flask(__name__, static_folder=".")

@app.route("/")
def inicio():
    return send_from_directory(".", "index.html")

@app.route("/api/health")
def health():
    return jsonify({"servidor": "online"})

@app.route("/api/cnpj")
def cnpj():
    numero = re.sub(r"\D", "", request.args.get("cnpj", ""))
    if len(numero) != 14 or len(set(numero)) == 1:
        return jsonify({"erro": "CNPJ inválido"}), 400
    try:
        r = requests.get(
            f"https://brasilapi.com.br/api/cnpj/v1/{numero}",
            timeout=15
        )
        return (r.text, r.status_code, {
            "Content-Type": "application/json"
        })
    except requests.RequestException:
        return jsonify({"erro": "Falha ao consultar BrasilAPI"}), 502

@app.route("/api/ip")
def ip():
    alvo = request.args.get("ip", "").strip()
    if alvo:
        try:
            ipaddress.ip_address(alvo)
        except ValueError:
            return jsonify({"erro": "IP inválido"}), 400

    resultados = []
    for nome, url in [
        ("ipwho.is", "https://ipwho.is/" + alvo),
        ("ipapi.co", f"https://ipapi.co/{alvo}/json/")
    ]:
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            d = r.json()
            if d.get("error") or d.get("success") is False:
                continue
            resultados.append({
                "fonte": nome,
                "ip": d.get("ip"),
                "pais": d.get("country") or d.get("country_name"),
                "regiao": d.get("region"),
                "cidade": d.get("city"),
                "cep": d.get("postal"),
                "latitude": d.get("latitude"),
                "longitude": d.get("longitude"),
                "fuso_horario": (
                    (d.get("timezone") or {}).get("id")
                    if isinstance(d.get("timezone"), dict)
                    else d.get("timezone")
                ),
                "provedor": (
                    (d.get("connection") or {}).get("isp")
                    if isinstance(d.get("connection"), dict)
                    else d.get("org")
                ),
                "asn": (d.get("connection") or {}).get("asn")
                if isinstance(d.get("connection"), dict)
                else d.get("asn")
            })
        except (requests.RequestException, ValueError):
            continue

    if not resultados:
        return jsonify({"erro": "Nenhuma fonte de IP respondeu"}), 502
    return jsonify({
        "aviso": "Localização por IP é aproximada.",
        "resultados": resultados
    })

@app.route("/api/email")
def email():
    endereco = request.args.get("email", "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", endereco):
        return jsonify({"erro": "E-mail inválido"}), 400

    resultado = {
        "email": endereco,
        "formato_valido": True,
        "avisos": []
    }
    chave = os.environ.get("HIBP_API_KEY", "").strip()
    if not chave:
        resultado["avisos"].append(
            "Configure HIBP_API_KEY para consultar vazamentos."
        )
        return jsonify(resultado)

    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            + requests.utils.quote(endereco, safe=""),
            headers={
                "hibp-api-key": chave,
                "user-agent": "PainelDoSabio"
            },
            params={"truncateResponse": "false"},
            timeout=20
        )
        if r.status_code == 200:
            dados = r.json()
            resultado["vazamentos_consultados"] = True
            resultado["quantidade"] = len(dados)
            resultado["vazamentos"] = [
                {
                    "nome": item.get("Name"),
                    "data": item.get("BreachDate")
                }
                for item in dados
            ]
        elif r.status_code == 404:
            resultado["vazamentos_consultados"] = True
            resultado["quantidade"] = 0
            resultado["mensagem"] = "Nenhum vazamento encontrado nessa consulta."
        else:
            resultado["avisos"].append(
                f"HIBP respondeu com status {r.status_code}."
            )
    except requests.RequestException:
        resultado["avisos"].append("Falha ao conectar ao HIBP.")
    return jsonify(resultado)

@app.route("/api/telefone")
def telefone():
    numero = request.args.get("telefone", "").strip()
    digitos = re.sub(r"\D", "", numero)
    if len(digitos) < 8 or len(digitos) > 15:
        return jsonify({"erro": "Confira o número informado"}), 400

    resultado = {
        "entrada": numero,
        "digitos": digitos,
        "aviso": "Não identifica titular nem localização em tempo real."
    }
    try:
        import phonenumbers
        analisado = phonenumbers.parse(
            numero if numero.startswith("+") else "+55" + digitos,
            None
        )
        resultado["valido"] = phonenumbers.is_valid_number(analisado)
        resultado["pais"] = phonenumbers.region_code_for_number(analisado)
        resultado["formato"] = phonenumbers.format_number(
            analisado, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
    except ImportError:
        resultado["aviso"] += " Instale phonenumbers para validar melhor."
    except Exception:
        resultado["valido"] = False
    return jsonify(resultado)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)


