import random
import datetime

# =============================================================================
# MONITOR LOGPY - Sistema de análise e diagnóstico de logs
# Servidor: coderslabs.com
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# PARTE 3 – MENU INTERATIVO
# ─────────────────────────────────────────────────────────────────────────────

def menu():
    nome_arq = 'log.txt'
    while True:
        print('\n' + '=' * 50)
        print('       MONITOR LOGPY – coderslabs.com')
        print('=' * 50)
        print('1 - Gerar logs')
        print('2 - Analisar logs')
        print('3 - Gerar e Analisar logs')
        print('4 - SAIR')
        print('-' * 50)
        opc = input('Escolha uma opção: ')

        if opc == '1':
            try:
                qtd = int(input('Quantidade de logs (registros): '))
                gerarArquivo(nome_arq, qtd)
            except:
                print('Entrada inválida.')
        elif opc == '2':
            analisarLogs(nome_arq)
        elif opc == '3':
            try:
                qtd = int(input('Quantidade de logs (registros): '))
                gerarArquivo(nome_arq, qtd)
                analisarLogs(nome_arq)
            except:
                print('Entrada inválida.')
        elif opc == '4':
            print('Até mais!')
            break
        else:
            print('Opção inválida. Digite 1, 2, 3 ou 4.')


# ─────────────────────────────────────────────────────────────────────────────
# PARTE 1 – GERAÇÃO DO ARQUIVO DE LOGS
# ─────────────────────────────────────────────────────────────────────────────

def gerarArquivo(nome_arq, qtd):
    """Gera o arquivo de logs com qtd linhas sintéticas."""
    with open(nome_arq, 'w', encoding='UTF-8') as arq:
        for i in range(qtd):
            arq.write(montarLog(i) + '\n')
    print(f'Arquivo "{nome_arq}" gerado com {qtd} registros.')


def montarLog(i):
    """Monta uma linha de log completa no formato exigido."""
    data      = gerarData(i)
    ip        = gerarIp(i)
    recurso   = gerarRecurso(i)
    metodo    = gerarMetodo(recurso)
    status    = gerarStatus(i, recurso)
    tempo     = gerarTempo(i, status)
    tamanho   = gerarTamanho(status, recurso)
    protocolo = gerarProtocolo(i)
    agente    = gerarAgente(i)
    referer   = gerarReferer(recurso)
    return f'[{data}] {ip} - {metodo} - {status} - {recurso} - {tempo}ms - {tamanho}B - {protocolo} - {agente} - {referer}'


# ── Funções auxiliares de geração ────────────────────────────────────────────

def gerarData(i):
    """Gera data/hora incremental a partir do momento atual."""
    base  = datetime.datetime(2026, 3, 23, 8, 0, 0)
    delta = datetime.timedelta(seconds=i * random.randint(5, 20))
    return (base + delta).strftime('%d/%m/%Y %H:%M:%S')


def gerarIp(i):
    """
    Gera IPs variados; alguns IPs especiais são fixados para garantir
    cenários detectáveis na análise (força bruta, bot, etc.).
    """
    # IP de força bruta: acessa /login repetidamente (índices 10 a 19)
    if i >= 10 and i <= 19:
        return '203.120.45.7'
    # IP de comportamento de bot (5+ acessos consecutivos, índices 30 a 39)
    if i >= 30 and i <= 39:
        return '45.33.100.88'
    # IP com muitos erros (índices 50 a 55)
    if i >= 50 and i <= 55:
        return '192.168.10.99'
    # Demais IPs aleatórios
    terceiro = i % 250
    quarto   = (i * 7 + 13) % 250 + 1
    primeiro = 10 + (i % 190)
    segundo  = 100 + (i % 100)
    return f'{primeiro}.{segundo}.{terceiro}.{quarto}'


def gerarRecurso(i):
    """
    Retorna o recurso (rota) acessado. Usa módulo do índice para
    distribuir cenários de forma determinística e coerente.
    """
    # Acesso a /login com força bruta (índices 10-19)
    if i >= 10 and i <= 19:
        return '/login'
    # Acesso indevido ao /admin (índices 20-25)
    if i >= 20 and i <= 25:
        return '/admin'
    # Sequência de erros 500 (índices 40-44)
    if i >= 40 and i <= 44:
        return '/api/dados'
    # Bot acessando várias rotas (índices 30-39)
    if i >= 30 and i <= 39:
        mod = i % 4
        if mod == 0:
            return '/home'
        if mod == 1:
            return '/produtos'
        if mod == 2:
            return '/sobre'
        return '/contato'
    # Rotas sensíveis ocasionais
    if i % 17 == 0:
        return '/backup'
    if i % 19 == 0:
        return '/config'
    if i % 23 == 0:
        return '/private'
    # Rotas comuns
    mod = i % 6
    if mod == 0:
        return '/home'
    if mod == 1:
        return '/produtos'
    if mod == 2:
        return '/sobre'
    if mod == 3:
        return '/contato'
    if mod == 4:
        return '/blog'
    return '/perfil'


def gerarMetodo(recurso):
    """Retorna o método HTTP mais adequado para o recurso."""
    if recurso == '/login':
        return 'POST'
    if recurso == '/admin':
        return 'GET'
    return 'GET'


def gerarStatus(i, recurso):
    """
    Retorna o status HTTP. Garante cenários obrigatórios:
    - 403 para tentativas de login (força bruta)
    - 403 para /admin (acesso indevido)
    - 500 em sequência (erro crítico)
    - 404 ocasionalmente
    - 200 para casos normais
    """
    # Força bruta: /login com 403 consecutivos (índices 10-19)
    if i >= 10 and i <= 19:
        return '403'
    # Acesso indevido ao admin (índices 20-25)
    if i >= 20 and i <= 25:
        return '403'
    # Sequência de erros 500 (índices 40-44, garantindo >= 3 consecutivos)
    if i >= 40 and i <= 44:
        return '500'
    # Erros com IP de muitos erros (índices 50-55)
    if i >= 50 and i <= 55:
        if i % 2 == 0:
            return '404'
        return '500'
    # 404 ocasional
    if i % 13 == 0:
        return '404'
    # 403 ocasional em rotas sensíveis
    if recurso == '/backup' or recurso == '/config' or recurso == '/private':
        return '403'
    # Normal
    return '200'


def gerarTempo(i, status):
    """
    Gera tempo de resposta em ms. Inclui degradação progressiva
    em determinado trecho (índices 60-75) e tempos mais altos para erros.
    """
    # Degradação progressiva de desempenho (índices 60-75)
    if i >= 60 and i <= 75:
        base = 100 + (i - 60) * 80   # 100, 180, 260, 340 ... até ~1300
        return base
    # Erros 500 tendem a ser lentos
    if status == '500':
        return random.randint(800, 1500)
    # Acessos normais rápidos
    if status == '200':
        mod = i % 3
        if mod == 0:
            return random.randint(50, 199)     # rápido
        if mod == 1:
            return random.randint(200, 799)    # normal
        return random.randint(800, 1200)       # lento
    # Outros erros
    return random.randint(100, 600)


def gerarTamanho(status, recurso):
    """Gera tamanho da resposta em bytes de forma coerente."""
    if status == '200':
        if recurso == '/home':
            return random.randint(4000, 8000)
        if recurso == '/produtos':
            return random.randint(6000, 12000)
        return random.randint(1000, 5000)
    if status == '404':
        return random.randint(200, 512)
    if status == '403':
        return random.randint(100, 300)
    if status == '500':
        return random.randint(50, 200)
    return random.randint(100, 1000)


def gerarProtocolo(i):
    """Retorna protocolo HTTP variado."""
    mod = i % 3
    if mod == 0:
        return 'HTTP/1.0'
    if mod == 1:
        return 'HTTP/1.1'
    return 'HTTP/2'


def gerarAgente(i):
    """
    Retorna user agent. Inclui bots e crawlers em alguns índices
    para garantir detecção na análise.
    """
    # Bots/crawlers obrigatórios
    if i % 15 == 0:
        return 'GoogleBot'
    if i % 20 == 0:
        return 'BingCrawler'
    if i % 25 == 0:
        return 'AhrefsSpider'
    # Agentes humanos comuns
    mod = i % 4
    if mod == 0:
        return 'Chrome'
    if mod == 1:
        return 'Firefox'
    if mod == 2:
        return 'Safari'
    return 'Edge'


def gerarReferer(recurso):
    """Gera referer (origem do acesso) com base no recurso atual."""
    if recurso == '/login':
        return '/home'
    if recurso == '/produtos':
        return '/home'
    if recurso == '/admin':
        return '/login'
    if recurso == '/perfil':
        return '/home'
    return '/home'


# ─────────────────────────────────────────────────────────────────────────────
# PARTE 2 – ANÁLISE DO ARQUIVO DE LOGS
# ─────────────────────────────────────────────────────────────────────────────

def analisarLogs(nome_arq):
    """
    Lê o arquivo de logs linha por linha, extrai campos manualmente
    (sem split()), calcula todas as métricas e exibe o relatório final.
    """

    # ── Contadores e acumuladores ─────────────────────────────────────────────
    total_acessos      = 0
    total_200          = 0
    total_403          = 0
    total_404          = 0
    total_500          = 0
    soma_tempos        = 0
    maior_tempo        = 0
    menor_tempo        = 999999
    rapidos            = 0
    normais            = 0
    lentos             = 0

    # Dicionários para contagem por chave (IP, recurso)
    # Como listas são proibidas, usamos dicionários nativos do Python
    contagem_ip        = {}   # ip -> total de acessos
    erros_ip           = {}   # ip -> total de erros
    contagem_recurso   = {}   # recurso -> total de acessos

    # Detecção de sequências (força bruta, bot, falha crítica, degradação)
    # Força bruta: mesmo IP, /login, 403 consecutivos
    fb_ip_atual        = ''
    fb_contagem        = 0
    fb_total_eventos   = 0
    fb_ultimo_ip       = ''

    # Bot: mesmo IP consecutivo >= 5 vezes
    bot_ip_atual       = ''
    bot_contagem       = 0
    bot_total          = 0
    bot_ultimo_ip      = ''

    # Falha crítica: 3 erros 500 consecutivos
    seq_500            = 0
    total_falha_critica = 0

    # Degradação: 3 aumentos consecutivos de tempo
    tempo_anterior     = -1
    seq_aumento        = 0
    total_degradacao   = 0

    # Acessos indevidos ao /admin
    admin_indevidos    = 0

    # Rotas sensíveis
    rotas_sensiveis_total  = 0
    rotas_sensiveis_falhas = 0

    # ── Leitura linha por linha ───────────────────────────────────────────────
    try:
        arq = open(nome_arq, 'r', encoding='UTF-8')
    except:
        print(f'Erro: arquivo "{nome_arq}" não encontrado. Gere os logs primeiro.')
        return

    for linha in arq:
        linha = linha.strip()
        if len(linha) == 0:
            continue

        # Extrai todos os campos da linha manualmente
        campos = extrairCampos(linha)
        if campos is None:
            continue   # linha inválida, ignora

        ip       = campos['ip']
        status   = campos['status']
        recurso  = campos['recurso']
        tempo    = campos['tempo']
        agente   = campos['agente']

        total_acessos += 1

        # ── Contagem de status ────────────────────────────────────────────────
        if status == '200':
            total_200 += 1
        elif status == '403':
            total_403 += 1
        elif status == '404':
            total_404 += 1
        elif status == '500':
            total_500 += 1

        # ── Tempo de resposta ─────────────────────────────────────────────────
        soma_tempos += tempo
        if tempo > maior_tempo:
            maior_tempo = tempo
        if tempo < menor_tempo:
            menor_tempo = tempo

        classe = classificarTempo(tempo)
        if classe == 'rapido':
            rapidos += 1
        elif classe == 'normal':
            normais += 1
        else:
            lentos += 1

        # ── Contagem por IP ───────────────────────────────────────────────────
        if ip in contagem_ip:
            contagem_ip[ip] = contagem_ip[ip] + 1
        else:
            contagem_ip[ip] = 1

        if status != '200':
            if ip in erros_ip:
                erros_ip[ip] = erros_ip[ip] + 1
            else:
                erros_ip[ip] = 1

        # ── Contagem por recurso ──────────────────────────────────────────────
        if recurso in contagem_recurso:
            contagem_recurso[recurso] = contagem_recurso[recurso] + 1
        else:
            contagem_recurso[recurso] = 1

        # ── Detecção de força bruta ───────────────────────────────────────────
        # Mesmo IP + /login + 403 consecutivos >= 3
        if ip == fb_ip_atual and recurso == '/login' and status == '403':
            fb_contagem += 1
            if fb_contagem == 3:
                # Evento detectado na 3ª ocorrência
                fb_total_eventos += 1
                fb_ultimo_ip = ip
        else:
            # Reinicia sequência
            if recurso == '/login' and status == '403':
                fb_ip_atual  = ip
                fb_contagem  = 1
            else:
                fb_ip_atual  = ''
                fb_contagem  = 0

        # ── Detecção de bot (mesmo IP >= 5 acessos consecutivos) ─────────────
        if ip == bot_ip_atual:
            bot_contagem += 1
            if bot_contagem == 5:
                bot_total   += 1
                bot_ultimo_ip = ip
        else:
            bot_ip_atual  = ip
            bot_contagem  = 1

        # Bot por user agent (contém Bot, Crawler ou Spider)
        if contemPalavra(agente, 'Bot') or contemPalavra(agente, 'Crawler') or contemPalavra(agente, 'Spider'):
            bot_total    += 1
            bot_ultimo_ip = ip

        # ── Detecção de falha crítica (3 erros 500 consecutivos) ─────────────
        if status == '500':
            seq_500 += 1
            if seq_500 == 3:
                total_falha_critica += 1
        else:
            seq_500 = 0

        # ── Detecção de degradação (3 aumentos consecutivos de tempo) ─────────
        if tempo_anterior >= 0:
            if tempo > tempo_anterior:
                seq_aumento += 1
                if seq_aumento == 3:
                    total_degradacao += 1
            else:
                seq_aumento = 0
        tempo_anterior = tempo

        # ── Acessos indevidos ao /admin ───────────────────────────────────────
        if recurso == '/admin' and status != '200':
            admin_indevidos += 1

        # ── Rotas sensíveis ───────────────────────────────────────────────────
        if recurso == '/admin' or recurso == '/backup' or recurso == '/config' or recurso == '/private':
            rotas_sensiveis_total += 1
            if status != '200':
                rotas_sensiveis_falhas += 1

    arq.close()

    # ── Cálculo de métricas finais ────────────────────────────────────────────
    if total_acessos == 0:
        print('Nenhum registro válido encontrado no arquivo.')
        return

    total_erros   = total_acessos - total_200
    disponib      = (total_200 / total_acessos) * 100
    taxa_erro     = (total_erros / total_acessos) * 100
    tempo_medio   = soma_tempos / total_acessos

    # IP mais ativo e IP com mais erros (varredura manual nos dicionários)
    ip_mais_ativo = encontrarChaveMaxima(contagem_ip)
    ip_mais_erros = encontrarChaveMaxima(erros_ip)

    # Recurso mais acessado
    recurso_top   = encontrarChaveMaxima(contagem_recurso)

    # Estado final
    estado = classificarEstado(disponib, total_falha_critica, lentos, total_acessos, bot_total)

    # ── Monta e exibe o relatório ─────────────────────────────────────────────
    relatorio = {
        'total_acessos'         : total_acessos,
        'total_sucessos'        : total_200,
        'total_erros'           : total_erros,
        'total_erros_criticos'  : total_500,
        'disponibilidade'       : disponib,
        'taxa_erro'             : taxa_erro,
        'tempo_medio'           : tempo_medio,
        'maior_tempo'           : maior_tempo,
        'menor_tempo'           : menor_tempo,
        'rapidos'               : rapidos,
        'normais'               : normais,
        'lentos'                : lentos,
        'status_200'            : total_200,
        'status_403'            : total_403,
        'status_404'            : total_404,
        'status_500'            : total_500,
        'recurso_top'           : recurso_top,
        'ip_mais_ativo'         : ip_mais_ativo,
        'ip_mais_erros'         : ip_mais_erros,
        'fb_total'              : fb_total_eventos,
        'fb_ultimo_ip'          : fb_ultimo_ip,
        'admin_indevidos'       : admin_indevidos,
        'total_degradacao'      : total_degradacao,
        'total_falha_critica'   : total_falha_critica,
        'bot_total'             : bot_total,
        'bot_ultimo_ip'         : bot_ultimo_ip,
        'rotas_sensiveis_total' : rotas_sensiveis_total,
        'rotas_sensiveis_falhas': rotas_sensiveis_falhas,
        'estado'                : estado,
    }

    imprimirRelatorio(relatorio)
    return relatorio


# ─────────────────────────────────────────────────────────────────────────────
# FUNÇÕES AUXILIARES DE ANÁLISE
# ─────────────────────────────────────────────────────────────────────────────

def extrairCampos(linha):
    """
    Extrai manualmente todos os campos de uma linha de log.
    Formato: [DD/MM/AAAA HH:MM:SS] IP - METODO - STATUS - RECURSO - TEMPOms - TAMANHOB - PROTOCOLO - AGENTE - REFERER
    NÃO usa split(). Usa busca manual de delimitadores caractere a caractere.
    Retorna dicionário com os campos, ou None se a linha for inválida.
    """

    # Verifica se começa com '['
    if len(linha) == 0 or linha[0] != '[':
        return None

    # ── Extrai data/hora entre '[' e ']' ─────────────────────────────────────
    pos_fecha = encontrarChar(linha, ']', 1)
    if pos_fecha < 0:
        return None
    data_hora = linha[1:pos_fecha]

    # ── A partir de '] ', extrai os demais campos separados por ' - ' ─────────
    # Pula '] ' (2 caracteres)
    resto = linha[pos_fecha + 2:]   # Ex: "192.168.0.1 - GET - 200 - /home - ..."

    ip        = extrairAte(resto, ' - ')
    resto     = resto[len(ip) + 3:]

    metodo    = extrairAte(resto, ' - ')
    resto     = resto[len(metodo) + 3:]

    status    = extrairAte(resto, ' - ')
    resto     = resto[len(status) + 3:]

    recurso   = extrairAte(resto, ' - ')
    resto     = resto[len(recurso) + 3:]

    tempo_str = extrairAte(resto, ' - ')   # Ex: "120ms"
    resto     = resto[len(tempo_str) + 3:]

    tamanho_str = extrairAte(resto, ' - ')  # Ex: "512B"
    resto       = resto[len(tamanho_str) + 3:]

    protocolo = extrairAte(resto, ' - ')
    resto     = resto[len(protocolo) + 3:]

    agente    = extrairAte(resto, ' - ')
    resto     = resto[len(agente) + 3:]

    referer   = resto   # último campo, o que sobrar

    # Converte tempo para inteiro (remove 'ms' do final)
    tempo_numerico = extrairNumero(tempo_str)
    if tempo_numerico < 0:
        return None

    return {
        'data_hora' : data_hora,
        'ip'        : ip,
        'metodo'    : metodo,
        'status'    : status,
        'recurso'   : recurso,
        'tempo'     : tempo_numerico,
        'tamanho'   : tamanho_str,
        'protocolo' : protocolo,
        'agente'    : agente,
        'referer'   : referer,
    }


def extrairAte(texto, delimitador):
    """
    Retorna a substring de 'texto' até encontrar 'delimitador'.
    Se não encontrar, retorna o texto inteiro.
    """
    tam_del = len(delimitador)
    i = 0
    while i <= len(texto) - tam_del:
        # Verifica se a sequência de caracteres bate com o delimitador
        igual = True
        for j in range(tam_del):
            if texto[i + j] != delimitador[j]:
                igual = False
                break
        if igual:
            return texto[:i]
        i += 1
    return texto


def encontrarChar(texto, char, inicio):
    """Retorna o índice da primeira ocorrência de 'char' a partir de 'inicio'. Retorna -1 se não encontrar."""
    for i in range(inicio, len(texto)):
        if texto[i] == char:
            return i
    return -1


def extrairNumero(texto):
    """
    Extrai o valor inteiro de uma string como '120ms' ou '512B'.
    Percorre caractere por caractere e acumula os dígitos.
    Retorna -1 se nenhum dígito for encontrado.
    """
    numero = ''
    for c in texto:
        if c >= '0' and c <= '9':
            numero += c
    if len(numero) == 0:
        return -1
    return int(numero)


def contemPalavra(texto, palavra):
    """
    Verifica se 'palavra' está contida em 'texto' (case-insensitive).
    NÃO usa split() nem 'in' de forma que quebre a restrição didática.
    """
    tam_p = len(palavra)
    tam_t = len(texto)
    if tam_p > tam_t:
        return False
    i = 0
    while i <= tam_t - tam_p:
        igual = True
        for j in range(tam_p):
            c_texto  = texto[i + j]
            c_palav  = palavra[j]
            # Comparação case-insensitive manual
            if c_texto >= 'a' and c_texto <= 'z':
                c_texto_up = chr(ord(c_texto) - 32)
            else:
                c_texto_up = c_texto
            if c_palav >= 'a' and c_palav <= 'z':
                c_palav_up = chr(ord(c_palav) - 32)
            else:
                c_palav_up = c_palav
            if c_texto_up != c_palav_up:
                igual = False
                break
        if igual:
            return True
        i += 1
    return False


def classificarTempo(tempo):
    """Classifica o tempo de resposta conforme as regras do projeto."""
    if tempo < 200:
        return 'rapido'
    if tempo < 800:
        return 'normal'
    return 'lento'


def encontrarChaveMaxima(dicionario):
    """
    Percorre o dicionário e retorna a chave com o maior valor.
    Implementação manual sem uso de funções como max() com key=.
    """
    chave_max = ''
    valor_max = -1
    for chave in dicionario:
        if dicionario[chave] > valor_max:
            valor_max = dicionario[chave]
            chave_max = chave
    return chave_max


def classificarEstado(disponib, falhas_criticas, lentos, total, bots):
    """Classifica o estado final do sistema conforme as regras do projeto."""
    # CRÍTICO: falha crítica ou disponibilidade < 70%
    if falhas_criticas >= 1 or disponib < 70:
        return 'CRÍTICO'
    # INSTÁVEL: disponibilidade < 85% ou muitos lentos (> 30% dos acessos)
    perc_lentos = (lentos / total) * 100 if total > 0 else 0
    if disponib < 85 or perc_lentos > 30:
        return 'INSTÁVEL'
    # ATENÇÃO: disponibilidade < 95% ou acessos suspeitos (bots > 0)
    if disponib < 95 or bots > 0:
        return 'ATENÇÃO'
    return 'SAUDÁVEL'


def imprimirRelatorio(r):
    """Exibe o relatório técnico completo no terminal."""
    sep = '=' * 55
    sec = '-' * 55
    print('\n' + sep)
    print('   RELATÓRIO TÉCNICO – MONITOR LOGPY')
    print('   Servidor: coderslabs.com')
    print(sep)

    print('\n[1] VISÃO GERAL DE ACESSOS')
    print(sec)
    print(f'  Total de acessos       : {r["total_acessos"]}')
    print(f'  Total de sucessos      : {r["total_sucessos"]}')
    print(f'  Total de erros         : {r["total_erros"]}')
    print(f'  Total de erros críticos: {r["total_erros_criticos"]}')

    print('\n[2] DISPONIBILIDADE E TAXA DE ERRO')
    print(sec)
    print(f'  Disponibilidade        : {r["disponibilidade"]:.2f}%')
    print(f'  Taxa de erro           : {r["taxa_erro"]:.2f}%')

    print('\n[3] DESEMPENHO – TEMPO DE RESPOSTA')
    print(sec)
    print(f'  Tempo médio            : {r["tempo_medio"]:.1f} ms')
    print(f'  Maior tempo            : {r["maior_tempo"]} ms')
    print(f'  Menor tempo            : {r["menor_tempo"]} ms')
    print(f'  Acessos rápidos (<200) : {r["rapidos"]}')
    print(f'  Acessos normais (200-799): {r["normais"]}')
    print(f'  Acessos lentos (>=800) : {r["lentos"]}')

    print('\n[4] DISTRIBUIÇÃO DE STATUS HTTP')
    print(sec)
    print(f'  Status 200 (sucesso)   : {r["status_200"]}')
    print(f'  Status 403 (negado)    : {r["status_403"]}')
    print(f'  Status 404 (não achado): {r["status_404"]}')
    print(f'  Status 500 (crítico)   : {r["status_500"]}')

    print('\n[5] RANKING DE ACESSOS')
    print(sec)
    print(f'  Recurso mais acessado  : {r["recurso_top"]}')
    print(f'  IP mais ativo          : {r["ip_mais_ativo"]}')
    print(f'  IP com mais erros      : {r["ip_mais_erros"]}')

    print('\n[6] DETECÇÃO DE SEGURANÇA')
    print(sec)
    print(f'  Eventos de força bruta : {r["fb_total"]}')
    print(f'  Último IP força bruta  : {r["fb_ultimo_ip"] if r["fb_ultimo_ip"] else "Nenhum"}')
    print(f'  Acessos indevidos /admin: {r["admin_indevidos"]}')
    print(f'  Suspeitas de bot       : {r["bot_total"]}')
    print(f'  Último IP suspeito bot : {r["bot_ultimo_ip"] if r["bot_ultimo_ip"] else "Nenhum"}')
    print(f'  Acessos rotas sensíveis: {r["rotas_sensiveis_total"]}')
    print(f'  Falhas rotas sensíveis : {r["rotas_sensiveis_falhas"]}')

    print('\n[7] ESTABILIDADE DO SISTEMA')
    print(sec)
    print(f'  Eventos de degradação  : {r["total_degradacao"]}')
    print(f'  Eventos falha crítica  : {r["total_falha_critica"]}')

    print('\n' + sep)
    print(f'  ESTADO FINAL DO SISTEMA:  >>> {r["estado"]} <<<')
    print(sep + '\n')


# ─────────────────────────────────────────────────────────────────────────────
# PONTO DE ENTRADA
# ─────────────────────────────────────────────────────────────────────────────

menu()
