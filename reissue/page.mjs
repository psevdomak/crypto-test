import { cryptoProAdapter } from './cryptopro.mjs';
import { reissue } from './flow.mjs';

const element = (id) => document.getElementById(id);
const form = element('setup');
const status = element('status');
const cleanup = element('cleanup');
const log = element('log');
let adapter;
let readerModes = [];

function report(message, details) {
    log.textContent += message + (details === undefined ? '' : '\n' + JSON.stringify(details, null, 2)) + '\n\n';
}

async function perform(operation) {
    const controls = form.querySelectorAll('fieldset');
    controls.forEach((fieldset) => { fieldset.disabled = true; });
    status.textContent = 'Выполняется…';
    try {
        if (!adapter) {
            const plugin = window.cadesplugin;
            if (!plugin) throw new Error('Скрипт КриптоПро не загрузился.');
            await plugin;
            adapter = cryptoProAdapter(plugin, report);
            try {
                report('Версии КриптоПро', await adapter.versions());
            } catch (error) {
                report('Версии КриптоПро недоступны', error.message || String(error));
            }
        }
        status.textContent = await operation();
    } catch (error) {
        const message = error.message || String(error);
        report('Ошибка', message);
        status.textContent = message;
    } finally {
        cleanup.disabled = !adapter?.owned().length;
        controls.forEach((fieldset) => { fieldset.disabled = false; });
    }
}

element('readers').addEventListener('click', () => perform(async () => {
    readerModes = await adapter.readers();
    report('Режимы считывателей', readerModes);
    for (const id of ['csp', 'pkcs11']) {
        const select = element(id);
        select.replaceChildren(new Option('Не задан', ''));
        readerModes.forEach(({ reader, media, flags }, index) => {
            const option = new Option(reader + ' | Media: ' + media + ' | флаги: ' + flags, index);
            option.disabled = !reader || !media;
            select.add(option);
        });
    }
    return 'Режимов считывателей: ' + readerModes.length;
}));

form.addEventListener('submit', (event) => {
    event.preventDefault();
    element('result').hidden = true;
    element('csr').value = '';
    perform(async () => {
        const modes = {};
        for (const [id, format] of [['csp', 'CSP'], ['pkcs11', 'PKCS11']]) {
            const value = element(id).value;
            if (value !== '') modes[format] = readerModes[Number(value)];
        }
        const serialNumber = element('serial').value.trim();
        const mockFormat = element('mock').value;
        const subject = element('subject').value.trim();
        if (!serialNumber || !subject || !Object.keys(modes).length) {
            throw new Error('Укажите серийный номер, субъект и хотя бы один контрольный считыватель.');
        }
        if (modes.CSP && modes.PKCS11 && modes.CSP.reader === modes.PKCS11.reader) {
            throw new Error('Для двух форматов нужны разные имена считывателей.');
        }
        if (mockFormat !== 'error' && !modes[mockFormat]) {
            throw new Error('Для ответа ' + mockFormat + ' укажите контрольный считыватель.');
        }
        const name = 'reissue-' + crypto.randomUUID();
        report('Запуск прогона', { name, mockFormat, modes });
        const result = await reissue({ adapter, modes, serialNumber, mockFormat, name, subject, report });
        element('csr').value = result.csr;
        element('result').hidden = false;
        return result.regenerated
            ? 'CSR создан повторно. Сверьте режим ключа на токене и число нативных диалогов.'
            : 'Сохранён первый CSR. Проверьте режим ключа на токене.';
    });
});

cleanup.addEventListener('click', () => perform(async () => {
    element('result').hidden = true;
    element('csr').value = '';
    for (const container of adapter.owned()) {
        await adapter.remove(container);
    }
    return 'Тестовые контейнеры удалены.';
}));
