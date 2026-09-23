// Popula a fixture do alvo 2 (D11) com a superficie publica padrao do produto:
// um monitor do tipo push, uma status page publicada contendo esse monitor e a
// pagina inicial apontando para ela. Tudo pelos mesmos eventos de socket.io
// que a interface usa. O monitor push apenas recebe requisicoes, sem gerar
// trafego de saida, o que mantem o runner independente de rede externa.
//
// Executado dentro do container por gerar_fixture.sh.
const { io } = require("/app/node_modules/socket.io-client");
const [usuario, senha] = process.argv.slice(2);

const PUSH_TOKEN = "tccPushToken2026E7x";
const SLUG = "servicos";

const s = io("http://localhost:3001");
const emit = (ev, ...a) => new Promise((r) => s.emit(ev, ...a, r));

function exigir(passo, res) {
    console.log(passo, JSON.stringify(res));
    if (!res || !res.ok) {
        process.exit(1);
    }
    return res;
}

s.on("connect", async () => {
    exigir("login", await emit("login", { username: usuario, password: senha, token: "" }));

    const monitor = exigir("monitor", await emit("add", {
        type: "push",
        name: "servico-exemplo",
        pushToken: PUSH_TOKEN,
        interval: 60,
        retryInterval: 60,
        maxretries: 0,
        notificationIDList: {},
        accepted_statuscodes: ["200-299"],
        conditions: [],
        kafkaProducerBrokers: [],
        kafkaProducerSaslOptions: {},
        rabbitmqNodes: [],
    }));

    exigir("status-page", await emit("addStatusPage", "Status dos Servicos", SLUG));
    exigir("status-page-config", await emit("saveStatusPage", SLUG, {
        slug: SLUG,
        title: "Status dos Servicos",
        description: "Pagina publica de status (fixture TCC)",
        logo: "/icon.svg",
        autoRefreshInterval: 300,
        theme: "auto",
        showTags: false,
        footerText: "",
        customCSS: "",
        showPoweredBy: true,
        rssTitle: "",
        showOnlyLastHeartbeat: false,
        showCertificateExpiry: false,
        analyticsId: null,
        analyticsScriptUrl: null,
        analyticsType: null,
        domainNameList: [],
    }, "/icon.svg", [{ name: "Servicos", monitorList: [{ id: monitor.monitorID }] }]));

    const settings = exigir("get-settings", await emit("getSettings"));
    settings.data.entryPage = "statusPage-" + SLUG;
    exigir("entry-page", await emit("setSettings", settings.data, ""));

    s.close();
    process.exit(0);
});

setTimeout(() => {
    console.error("timeout ao popular a fixture");
    process.exit(1);
}, 30000);
