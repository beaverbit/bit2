# Política de Segurança

## Versões suportadas

Apenas a versão mais recente da branch `main` recebe correções de segurança.

| Versão | Suportada          |
| ------ | ------------------ |
| 0.3.x  | :white_check_mark: |
| < 0.3  | :x:                |

## Escopo

O `bit2` é uma ferramenta de reconhecimento de rede. As vulnerabilidades que interessam são:

- Falhas que permitam **execução remota** a partir de um alvo malicioso (ex: banner grabbing com payload malicioso)
- **Crash** ou consumo de memória descontrolado ao processar resposta de alvo
- **Vazamento de informação** local (ex: senhas, tokens, arquivos pessoais)
- **Bypass** de restrições que permitam escanear fora do escopo pretendido sem intenção do usuário

**Fora do escopo:**

- A própria natureza do scan gerar tráfego detectável (isso é esperado)
- Detecção de serviço imprecisa (é limitação documentada no README)
- Uso da ferramenta para fins ilegais (é responsabilidade do usuário, ver aviso legal no README)

## Reportando uma vulnerabilidade

**Não abra uma issue pública** para vulnerabilidades de segurança.

Envie um e-mail para o autor via o endereço listado no perfil do GitHub ([@beaverbit](https://github.com/beaverbit)), com:

- Descrição do problema
- Passos pra reproduzir
- Versão do `bit2` afetada
- Impacto estimado
- Se possível, sugestão de correção

**Resposta esperada:** confirmação em até 7 dias, correção em até 30 dias (não é trabalho full-time, é projeto pessoal).

## Divulgação responsável

Após a correção ser publicada, você pode divulgar o problema publicamente. Se quiser crédito, mencione como prefere ser citado no e-mail.
