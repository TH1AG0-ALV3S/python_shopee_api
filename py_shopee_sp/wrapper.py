import hashlib
import hmac
from time import sleep, time
import requests


class ShopeeAPIError(Exception):
    """Exceção base para erros da Shopee Open API."""
    def __init__(self, message, status_code=None, error_code=None, response_data=None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.response_data = response_data


class RateLimitExceededError(ShopeeAPIError):
    """Exceção para quando o rate limit é excedido e as tentativas de retry se esgotam."""
    pass


class auth():
    """Classe base com autenticação e controle de requisições para a Shopee Open API v2.

    A Shopee Open API v2 exige que toda requisição seja assinada com HMAC-SHA256
    no momento do envio. A assinatura é calculada a partir de uma base string que
    combina partner_id, caminho da API, timestamp, access_token e shop_id (ou
    merchant_id). Os parâmetros de autenticação são enviados na query string.

    Rate limiting: a Shopee não publica limites numéricos fixos. O controle é feito
    de forma reativa: em caso de HTTP 429 ou erro JSON com 'rate_limit', a requisição
    é retentada com backoff exponencial (1s → 2s → 4s), até _MAX_RETRIES tentativas.

    Referência: https://open.shopee.com/developer-guide/16
    """

    _ENDPOINTS = {
        'sg': 'https://partner.shopeemobile.com',          # Padrão — servidor próximo a SG
        'br': 'https://openplatform.shopee.com.br',         # Servidor próximo aos EUA/BR
        'cn': 'https://openplatform.shopee.cn',             # Mainland China
        'sandbox': 'https://openplatform.sandbox.test-stable.shopee.sg',  # Testes
    }

    _MAX_RETRIES = 3

    def __init__(self, partner_id, partner_key, access_token="", shop_id=None,
                 merchant_id=None, env="sg", print_error=True):
        """
        Args:
            partner_id (int): ID do parceiro (App), obtido no Shopee Open Platform Console.
            partner_key (str): Chave do parceiro (App), obtida no Console.
            access_token (str): Token de acesso do vendedor autorizado. Válido por 4h.
            shop_id (int | None): ID da loja autorizada. Obrigatório para Shop APIs.
            merchant_id (int | None): ID do merchant. Usado apenas por sellers cross-border.
            env (str): Ambiente do endpoint ('sg', 'br', 'cn', 'sandbox').
            print_error (bool): Se True, imprime detalhes de erros no console.
        """
        if env not in self._ENDPOINTS:
            raise ValueError(f"Ambiente inválido. Escolha entre: {', '.join(self._ENDPOINTS.keys())}")

        self.partner_id = partner_id
        self.partner_key = partner_key
        self.access_token = access_token
        self.shop_id = shop_id
        self.merchant_id = merchant_id
        self.env = env
        self.endpoint = self._ENDPOINTS[env]
        self.print_error = print_error

    def _generate_sign(self, api_path, timestamp, access_token="", shop_id=None, merchant_id=None):
        """Calcula a assinatura HMAC-SHA256 para uma requisição.

        A base string varia conforme o tipo de API:
        - Shop API:     partner_id + api_path + timestamp + access_token + shop_id
        - Merchant API: partner_id + api_path + timestamp + access_token + merchant_id
        - Public API:   partner_id + api_path + timestamp

        Args:
            api_path (str): Caminho da API sem o host. Ex: '/api/v2/order/get_order_list'.
            timestamp (int): Unix epoch em segundos.
            access_token (str): Token de acesso (vazio para Public APIs).
            shop_id (int | None): ID da loja (Shop APIs).
            merchant_id (int | None): ID do merchant (Merchant APIs).

        Returns:
            str: Assinatura hexadecimal em letras minúsculas.
        """
        if shop_id is not None:
            base_string = f"{self.partner_id}{api_path}{timestamp}{access_token}{shop_id}"
        elif merchant_id is not None:
            base_string = f"{self.partner_id}{api_path}{timestamp}{access_token}{merchant_id}"
        else:
            base_string = f"{self.partner_id}{api_path}{timestamp}"

        return hmac.new(
            self.partner_key.encode(),
            base_string.encode(),
            hashlib.sha256
        ).hexdigest()

    def request(self, method="GET", path="", params=None, body=None):
        """Método unificado para requisições à Shopee Open API v2.

        Assina automaticamente cada requisição com HMAC-SHA256 e adiciona os
        parâmetros comuns (partner_id, timestamp, sign, access_token, shop_id)
        à query string. Em caso de rate limit (HTTP 429 ou erro JSON com
        'rate_limit'), retenta com backoff exponencial até _MAX_RETRIES vezes.

        Args:
            method (str): Método HTTP ('GET' ou 'POST').
            path (str): Caminho da API sem o host. Ex: '/api/v2/order/get_order_list'.
            params (dict | None): Parâmetros de query string adicionais (além dos comuns).
            body (dict | None): Corpo da requisição para métodos POST.

        Returns:
            requests.Response: Objeto de resposta em caso de sucesso.
            None: Em caso de erro HTTP 403 ou 404.
        """
        url = self.endpoint + path
        req_params = params.copy() if params is not None else {}

        timestamp = int(time())
        sign = self._generate_sign(
            api_path=path,
            timestamp=timestamp,
            access_token=self.access_token,
            shop_id=self.shop_id,
            merchant_id=self.merchant_id,
        )

        common_params = {
            "partner_id": self.partner_id,
            "timestamp": timestamp,
            "sign": sign,
        }
        if self.access_token:
            common_params["access_token"] = self.access_token
        if self.shop_id is not None:
            common_params["shop_id"] = self.shop_id
        elif self.merchant_id is not None:
            common_params["merchant_id"] = self.merchant_id

        req_params.update(common_params)

        headers = {"Content-Type": "application/json"}

        retries = 0
        delay = 1

        while True:
            if method == "GET":
                response = requests.get(url=url, params=req_params, headers=headers)
            else:
                response = requests.post(url=url, params=req_params, json=body, headers=headers)

            # A Shopee retorna HTTP 200 mesmo em erros de lógica; é necessário
            # checar o campo JSON 'error'. Respostas de arquivo (download) não
            # têm JSON, por isso o bloco try/except.
            is_rate_limit = response.status_code == 429
            error_code = ""
            if not is_rate_limit:
                try:
                    resp_json = response.json()
                    error_code = resp_json.get("error", "")
                    if "rate_limit" in error_code:
                        is_rate_limit = True
                except Exception:
                    pass

            if is_rate_limit:
                retries += 1
                if retries > self._MAX_RETRIES:
                    raise RateLimitExceededError(
                        f"Rate limit excedido após {self._MAX_RETRIES} tentativas. Tente novamente mais tarde.",
                        status_code=response.status_code,
                        error_code=error_code,
                    )
                if self.print_error:
                    print(
                        f"Rate limit atingido. "
                        f"Aguardando {delay}s antes de retentar "
                        f"(tentativa {retries}/{self._MAX_RETRIES})..."
                    )
                sleep(delay)
                delay *= 2
                continue

            if response.status_code in (403, 404):
                if self.print_error:
                    print(f"Erro HTTP {response.status_code} — URL: {url}")
                return None

            if response.status_code not in (200, 201):
                if self.print_error:
                    try:
                        json_content = response.json()
                        message = json_content.get("message", "")
                    except Exception:
                        message = ""
                        json_content = response.text
                    print(f"""Erro no retorno da Shopee Open API
Mensagem: {message}
URL: {url}
Método: {method}
Parâmetros: {req_params}
Corpo: {body}
Resposta: {json_content}""")
                break

            # Verifica erros de lógica embutidos no JSON (HTTP 200 com error != "")
            if error_code and self.print_error:
                try:
                    resp_json = response.json()
                    message = resp_json.get("message", "")
                except Exception:
                    message = ""
                print(f"""Erro retornado pela Shopee Open API
Código: {error_code}
Mensagem: {message}
URL: {url}
Método: {method}
Parâmetros: {req_params}""")

            return response

    def get_access_token(self, code, shop_id=None, main_account_id=None):
        """Obtém o access_token pela primeira vez após autorização do vendedor.

        Após o vendedor autorizar o App, use o 'code' retornado na URL de callback
        para obter o par inicial de access_token e refresh_token.

        Args:
            code (str): Código de autorização recebido na URL de callback.
            shop_id (int | None): ID da loja autorizada (para autorização via conta da loja).
            main_account_id (int | None): ID da conta principal (para autorização via conta principal).

        Returns:
            dict: Resposta da API contendo access_token, refresh_token, expire_in, etc.
                  Retorna dict vazio em caso de falha.
        """
        path = "/api/v2/auth/token/get"
        timestamp = int(time())
        sign = self._generate_sign(api_path=path, timestamp=timestamp)

        query_params = {
            "partner_id": self.partner_id,
            "timestamp": timestamp,
            "sign": sign,
        }

        body = {"code": code, "partner_id": self.partner_id}
        if shop_id is not None:
            body["shop_id"] = shop_id
        elif main_account_id is not None:
            body["main_account_id"] = main_account_id

        response = requests.post(
            url=self.endpoint + path,
            params=query_params,
            json=body,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 200:
            return response.json()

        if self.print_error:
            print(f"Erro ao obter access_token: HTTP {response.status_code} — {response.text}")
        return {}

    def refresh_access_token(self, refresh_token, shop_id=None, merchant_id=None):
        """Renova o access_token usando o refresh_token.

        Deve ser chamado antes do access_token expirar (validade de 4h). Após a
        chamada, o novo refresh_token retornado deve ser salvo — o anterior se
        torna inválido.

        Args:
            refresh_token (str): Token de renovação. Válido por 30 dias.
            shop_id (int | None): ID da loja (shops locais).
            merchant_id (int | None): ID do merchant (sellers cross-border).

        Returns:
            dict: Resposta da API contendo o novo access_token, refresh_token e expire_in.
                  Retorna dict vazio em caso de falha.
        """
        path = "/api/v2/auth/access_token/get"
        timestamp = int(time())
        sign = self._generate_sign(api_path=path, timestamp=timestamp)

        query_params = {
            "partner_id": self.partner_id,
            "timestamp": timestamp,
            "sign": sign,
        }

        body = {"refresh_token": refresh_token, "partner_id": self.partner_id}
        if shop_id is not None:
            body["shop_id"] = shop_id
        elif merchant_id is not None:
            body["merchant_id"] = merchant_id

        response = requests.post(
            url=self.endpoint + path,
            params=query_params,
            json=body,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 200:
            return response.json()

        if self.print_error:
            print(f"Erro ao renovar access_token: HTTP {response.status_code} — {response.text}")
        return {}


class order(auth):
    """Operações do módulo Order da Shopee Open API v2, com foco em notas fiscais (BR).

    Documentação: https://open.shopee.com/documents/v2/v2.order.get_pending_buyer_invoice_order_list
    """

    def get_pending_invoice_orders(self, page_size=50, cursor=""):
        """Lista pedidos pendentes de upload de nota fiscal.

        Esta rota está disponível apenas para sellers locais do Brasil e Filipinas.

        Args:
            page_size (int): Quantidade de resultados por página (1–100). Padrão: 50.
            cursor (str): Cursor de paginação. Deixe vazio "" para a primeira página.

        Returns:
            dict: Resposta contendo 'order_list', 'more' e 'next_cursor',
                  ou dict vazio em caso de falha.
        """
        path = "/api/v2/order/get_pending_buyer_invoice_order_list"
        params = {"page_size": page_size, "cursor": cursor}

        response = self.request("GET", path=path, params=params)

        if response:
            return response.json()
        return {}

    def upload_invoice(self, order_sn, invoice_doc, doc_type="XML"):
        """Faz upload de uma nota fiscal para um pedido.

        Args:
            order_sn (str): Identificador único do pedido na Shopee.
            invoice_doc (bytes | str): Conteúdo do arquivo da NF-e (XML ou PDF).
            doc_type (str): Tipo do documento ('XML' ou 'PDF'). Padrão: 'XML'.

        Returns:
            dict: Resposta da API ou dict vazio em caso de falha.
        """
        path = "/api/v2/order/upload_invoice_doc"

        timestamp = int(time())
        sign = self._generate_sign(
            api_path=path,
            timestamp=timestamp,
            access_token=self.access_token,
            shop_id=self.shop_id,
            merchant_id=self.merchant_id,
        )

        query_params = {
            "partner_id": self.partner_id,
            "timestamp": timestamp,
            "sign": sign,
            "access_token": self.access_token,
        }
        if self.shop_id is not None:
            query_params["shop_id"] = self.shop_id

        files = {
            "order_sn": (None, order_sn),
            "doc_type": (None, doc_type),
            "invoice_doc": ("invoice", invoice_doc if isinstance(invoice_doc, bytes) else invoice_doc.encode()),
        }

        response = requests.post(
            url=self.endpoint + path,
            params=query_params,
            files=files,
        )

        if response and response.status_code == 200:
            data = response.json()
            error_code = data.get("error", "")
            if error_code and self.print_error:
                print(f"Erro ao fazer upload da NF — Código: {error_code} | Mensagem: {data.get('message', '')}")
            return data

        if self.print_error:
            print(f"Erro HTTP {response.status_code} ao fazer upload da NF para o pedido {order_sn}")
        return {}

    def download_invoice(self, order_sn):
        """Faz download do arquivo de nota fiscal de um pedido.

        Esta rota está disponível apenas para sellers locais do Brasil e Filipinas.
        Retorna o conteúdo binário do arquivo (XML ou PDF).

        Args:
            order_sn (str): Identificador único do pedido na Shopee.

        Returns:
            bytes: Conteúdo binário do arquivo da NF-e, ou b'' em caso de falha.
        """
        path = "/api/v2/order/download_invoice_doc"
        params = {"order_sn": order_sn}

        response = self.request("GET", path=path, params=params)

        if response:
            return response.content
        return b""

    def download_invoices_batch(self, order_sns):
        """Faz download das notas fiscais de múltiplos pedidos.

        A Shopee não oferece endpoint de download em lote; este método itera
        sobre a lista chamando download_invoice() individualmente.

        Args:
            order_sns (list[str]): Lista de order_sn dos pedidos.

        Returns:
            dict[str, bytes]: Dicionário {order_sn: conteúdo_binário}.
                              Pedidos com falha retornam b''.
        """
        return {order_sn: self.download_invoice(order_sn) for order_sn in order_sns}

    def get_order_list(self, time_from, time_to, time_range_field="create_time",
                       page_size=50, order_status=None, cursor=""):
        """Lista pedidos por período.

        Consulta a rota GET /api/v2/order/get_order_list da Shopee Open API v2.
        Retorna pedidos do intervalo [time_from, time_to] com paginação por cursor.

        O intervalo máximo permitido pela Shopee é de 15 dias. Para períodos maiores,
        chame o método em loop incrementando time_from e usando next_cursor até
        que 'more' seja False.

        Exemplo de uso:
            from time import time
            time_to   = int(time())
            time_from = time_to - 7 * 24 * 3600  # últimos 7 dias

            result = client.get_order_list(time_from, time_to, order_status="SHIPPED")
            orders   = result.get("order_list", [])
            has_more = result.get("more", False)
            cursor   = result.get("next_cursor", "")

        Args:
            time_from (int): Unix timestamp de início do intervalo (inclusive).
            time_to (int): Unix timestamp de fim do intervalo (inclusive).
            time_range_field (str): Campo usado como referência de tempo.
                - 'create_time' — filtra pela data de criação do pedido (padrão).
                - 'update_time' — filtra pela data da última atualização.
            page_size (int): Quantidade de pedidos por página (1–100). Padrão: 50.
            order_status (str | None): Filtro opcional de status. Valores aceitos:
                UNPAID, READY_TO_SHIP, PROCESSED, SHIPPED, COMPLETED,
                IN_CANCEL, CANCELLED, INVOICE_PENDING. None retorna todos.
            cursor (str): Cursor de paginação retornado em 'next_cursor' pela
                chamada anterior. Deixe vazio "" para a primeira página.

        Returns:
            dict: Dicionário com as chaves:
                - 'order_list' (list[dict]): Lista de pedidos. Cada item contém
                  'order_sn', 'order_status' e campos de tempo.
                - 'more' (bool): True se há mais páginas disponíveis.
                - 'next_cursor' (str): Cursor a passar na próxima chamada.
                Retorna dict vazio {} em caso de falha na requisição.
        """
        path = "/api/v2/order/get_order_list"
        params = {
            "time_range_field": time_range_field,
            "time_from": time_from,
            "time_to": time_to,
            "page_size": page_size,
            # Solicita order_status na resposta mesmo sem filtro de status ativo
            "response_optional_fields": "order_status",
        }
        if order_status:
            # Filtra apenas pedidos com o status especificado
            params["order_status"] = order_status
        if cursor:
            # Inclui cursor apenas a partir da segunda página em diante
            params["cursor"] = cursor

        response = self.request("GET", path=path, params=params)
        if response:
            data = response.json()
            # A Shopee encapsula os dados úteis dentro da chave 'response'
            return data.get("response", {})
        return {}

    def get_order_detail(self, order_sn_list, response_optional_fields="invoice_data"):
        """Retorna detalhes completos de um ou mais pedidos.

        Consulta a rota GET /api/v2/order/get_order_detail da Shopee Open API v2.
        Útil para obter dados como endereço de entrega, itens, valores e,
        no caso de sellers BR, o invoice_data com a access_key da NF-e.

        A Shopee limita 50 order_sn por chamada. Para lotes maiores, divida a
        lista em chunks de 50 e chame o método para cada chunk.

        Exemplo de uso:
            # Detalhes básicos
            result = client.get_order_detail(["2504XXXXXXXX", "2504YYYYYYYY"])
            orders = result.get("order_list", [])

            # Detalhes com múltiplos campos opcionais
            result = client.get_order_detail(
                ["2504XXXXXXXX"],
                response_optional_fields="invoice_data,buyer_user_id,buyer_username"
            )

        Args:
            order_sn_list (list[str]): Lista de order_sn dos pedidos desejados.
                Máximo de 50 itens por chamada.
            response_optional_fields (str): Campos adicionais separados por vírgula.
                Padrão: 'invoice_data' (retorna dados da NF-e para sellers BR).
                Outros valores comuns: 'buyer_user_id', 'buyer_username',
                'estimated_shipping_fee', 'actual_shipping_fee'.

        Returns:
            dict: Dicionário com a chave:
                - 'order_list' (list[dict]): Lista de pedidos com todos os detalhes.
                  Cada item inclui order_sn, order_status, recipient_address,
                  item_list, total_amount e, se solicitado, invoice_data.
                Retorna dict vazio {} em caso de falha na requisição.
        """
        path = "/api/v2/order/get_order_detail"
        params = {
            # A API espera os order_sn como string única separada por vírgulas
            "order_sn_list": ",".join(order_sn_list),
            "response_optional_fields": response_optional_fields,
        }

        response = self.request("GET", path=path, params=params)
        if response:
            data = response.json()
            # A Shopee encapsula os dados úteis dentro da chave 'response'
            return data.get("response", {})
        return {}
