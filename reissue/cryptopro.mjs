export function cryptoProAdapter(plugin, report) {
    const owned = new Map();

    function run(operation) {
        return new Promise((resolve, reject) => {
            plugin.async_spawn(function* () {
                try {
                    const about = yield plugin.CreateObjectAsync('CAdESCOM.About');
                    const provider = yield about.CSPName(80);
                    const info = yield plugin.CreateObjectAsync('X509Enrollment.CCspInformation');
                    yield info.InitializeFromName(provider);
                    resolve(yield* operation({ about, provider, info }));
                } catch (error) {
                    reject(error);
                }
            });
        });
    }

    function* versions({ about, provider }) {
        const pluginVersion = yield about.PluginVersion;
        const cspVersion = yield about.CSPVersion(provider, 80);
        return { plugin: yield pluginVersion.toString(), csp: yield cspVersion.toString(), provider };
    }

    function* readers({ info }) {
        const modes = yield info.GetReaderModes();
        const count = yield modes.Count;
        const entries = [];
        for (let i = 0; i < count; i++) {
            const mode = yield modes.ItemByIndex(i);
            entries.push({
                reader: yield mode.Name,
                media: yield mode.Media,
                label: yield mode.NickName,
                flags: yield mode.CarrierFlags,
            });
        }
        return entries;
    }

    function* call(stage, operation) {
        try {
            return yield operation();
        } catch (error) {
            throw new Error(stage + ': ' + (error?.message || String(error)), { cause: error });
        }
    }

    function hasErrorCode(error, codes) {
        const message = error?.message || String(error);
        const fromMessage = message.match(/0x([0-9a-f]{8})/i);
        const code = fromMessage ? Number.parseInt(fromMessage[1], 16) : Number(error?.number ?? error?.code);
        return codes.includes(code >>> 0);
    }

    function* containers(info, phase) {
        const stage = 'Перечисление контейнеров (' + phase + ')';
        let collection;
        try {
            collection = yield* call(stage + ': EnumContainers', () => info.EnumContainers());
        } catch (error) {
            if (!hasErrorCode(error.cause ?? error, [0x80070103])) throw error;
            report('EnumContainers недоступен. Используется точечный поиск.', { phase, error: error.message });
            return null;
        }
        const count = yield* call(stage + ': Count', () => collection.Count);
        const entries = [];
        for (let i = 0; i < count; i++) {
            const entry = stage + ', элемент ' + (i + 1) + ' из ' + count;
            const object = yield* call(entry + ': ItemByIndex', () => collection.ItemByIndex(i));
            const id = yield* call(entry + ': UniqueName', () => object.UniqueName);
            entries.push({ object, id });
        }
        return entries;
    }

    function* metadata({ object, id }) {
        return { id, fqcn: yield object.FQCN, reader: yield object.Reader, media: yield object.Media };
    }

    function* containerById(info, keyId) {
        let object;
        try {
            object = yield* call('ContainerByName', () => info.ContainerByName(keyId));
        } catch (error) {
            const notFound = [0x80070002, 0x80090016, 0x80092004];
            if (hasErrorCode(error.cause ?? error, notFound)) return null;
            throw error;
        }
        if (object == null) return null;
        const id = yield* call('ContainerByName: UniqueName', () => object.UniqueName);
        const fqcn = yield* call('ContainerByName: FQCN', () => object.FQCN);
        if (!id || (id !== keyId && fqcn !== keyId)) {
            throw new Error('ContainerByName вернул контейнер с другим идентификатором.');
        }
        return { object, id, fqcn };
    }

    function* createRequest(provider, container, subject, filter) {
        const key = yield plugin.CreateObjectAsync('X509Enrollment.CX509PrivateKey');
        yield key.propset_ProviderName(provider);
        yield key.propset_ContainerName(container);
        yield key.propset_ProviderType(80);
        yield key.propset_ExportPolicy(0);
        yield key.propset_KeySpec(1);
        yield key.propset_Existing(false);

        const request = yield plugin.CreateObjectAsync('X509Enrollment.CX509CertificateRequestPkcs10');
        yield* call('InitializeFromPrivateKey', () => request.InitializeFromPrivateKey(1, key, ''));
        const name = yield plugin.CreateObjectAsync('X509Enrollment.CX500DistinguishedName');
        yield name.Encode(subject);
        yield request.propset_Subject(name);
        const usage = yield plugin.CreateObjectAsync('X509Enrollment.CX509ExtensionKeyUsage');
        yield usage.InitializeEncode(32 | 16 | 128 | 64 | 8);
        const identification = yield plugin.CreateObjectAsync('X509Enrollment.CX509ExtensionIdentificationKind');
        yield identification.InitializeEncode(0);
        const extensions = yield request.X509Extensions;
        yield extensions.Add(usage);
        yield extensions.Add(identification);

        const enrollment = yield plugin.CreateObjectAsync('X509Enrollment.CX509Enrollment');
        yield* call('InitializeFromRequest', () => enrollment.InitializeFromRequest(request));
        report('Вызов CreateRequest', { container, filter });
        const csr = yield* call('CreateRequest', () => enrollment.CreateRequest(plugin.XCN_CRYPT_STRING_BASE64));
        report('CreateRequest вернул CSR', { container });

        let keyId;
        try {
            keyId = yield key.UniqueContainerName;
        } catch (error) {
            report('UniqueContainerName недоступно', error.message || String(error));
        }
        return { csr, keyId };
    }

    function escapePattern(value) {
        return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function readerFormat({ media, flags }) {
        if (/^pkcs11_/i.test(media)) return 'PKCS11';
        if (/^rutoken_(fkc|crypt)_/i.test(media) || (flags & plugin.CARRIER_FLAG_SECURE_MESSAGING)) return undefined;
        if (Number.isInteger(flags) && !(flags & plugin.CARRIER_FLAG_FUNCTIONAL_CARRIER)) return 'CSP';
        return undefined;
    }

    function* initialFilter(context, formats) {
        const types = {
            CSP: plugin.ENABLE_CARRIER_TYPE_CSP,
            PKCS11: plugin.ENABLE_CARRIER_TYPE_FKC_NO_SM,
        };
        const type = formats.reduce((mask, format) => mask | types[format], 0);
        if (formats.length === 1 && formats[0] === 'CSP') {
            return { type, regex: '.*', formats };
        }

        const modes = yield* readers(context);
        const media = [...new Set(modes
            .filter((mode) => mode.media && mode.media !== 'NO_MEDIA' && formats.includes(readerFormat(mode)))
            .map((mode) => mode.media))];
        if (!media.length) {
            report('Доступные режимы считывателей', modes);
            throw new Error('Среди подключённых носителей нет выбранных режимов ReaderFilter.');
        }
        return { type, regex: '^(' + media.map(escapePattern).join('|') + ')$', formats, media };
    }

    function* generate(context, name, subject, options = {}) {
        const { about, provider, info } = context;
        const existing = yield* containers(info, 'до генерации');
        const before = new Set(existing?.map(({ id }) => id));
        let container = name;
        let filter;
        const { keyFormat, reader, media, readerFormats = [], smartCardsOnly = false } = options;
        if (reader) {
            if (reader.includes('\\')) {
                throw new Error('Имя считывателя содержит разделитель полного имени контейнера.');
            }
            const type = keyFormat === 'CSP'
                ? plugin.ENABLE_CARRIER_TYPE_CSP
                : plugin.ENABLE_CARRIER_TYPE_FKC_NO_SM;
            // ReaderFilter passes the operating-mode pattern to PP_UNIQUE_FILTER.
            filter = { type, regex: '^' + escapePattern(media) + '$', media };
            container = ['\\\\.', reader, name].join('\\');
        } else if (readerFormats.length) {
            filter = yield* initialFilter(context, readerFormats);
        }

        let request;
        if (filter) {
            const operations = plugin.DISABLE_EVERY_CARRIER_OPERATION;
            let mediaType;
            let generationFailed = false;
            try {
                if (smartCardsOnly) {
                    mediaType = plugin.MEDIA_TYPE_SCARD;
                    yield* call('MediaFilter: смарт-карты', () => about.MediaFilter(mediaType));
                }
                yield* call('ReaderFilter: установка', () => about.ReaderFilter(filter.type, operations, filter.regex));
                request = yield* createRequest(provider, container, subject, { ...filter, operations, mediaType });
            } catch (error) {
                generationFailed = true;
                throw error;
            } finally {
                let resetError;
                try {
                    yield* call('ReaderFilter: сброс', () =>
                        about.ReaderFilter(plugin.ENABLE_ANY_CARRIER_TYPE, plugin.ENABLE_ANY_OPERATION, '.*'));
                } catch (error) {
                    resetError = error;
                    report('Сбой сброса ReaderFilter', error.message);
                }
                if (mediaType !== undefined) {
                    try {
                        yield* call('MediaFilter: сброс', () => about.MediaFilter(plugin.MEDIA_TYPE_DEFAULT));
                    } catch (error) {
                        resetError ??= error;
                        report('Сбой сброса MediaFilter', error.message);
                    }
                }
                if (!generationFailed && resetError) throw resetError;
            }
        } else {
            request = yield* createRequest(provider, container, subject, null);
        }

        const after = existing && (yield* containers(info, 'после генерации'));
        let created;
        if (after) {
            created = yield* findNewContainer(after, before, request, name);
        } else {
            if (!request.keyId) {
                throw new Error('Для точечного поиска не удалось получить UniqueContainerName созданного ключа.');
            }
            const entry = yield* containerById(info, request.keyId);
            if (!entry || before.has(entry.id) || owned.has(entry.id)) {
                throw new Error('ContainerByName не подтвердил создание нового контейнера.');
            }
            const actualName = yield* call('ContainerByName: Name', () => entry.object.Name);
            if (!matchesContainerName(name, actualName, entry.fqcn)) {
                throw new Error('Имя найденного контейнера отличается от имени текущего прогона.');
            }
            created = yield* metadata(entry);
        }
        owned.set(created.id, created);
        report('Создан контейнер', created);
        return { ...created, csr: request.csr };
    }

    function matchesContainerName(name, ...values) {
        return values.some((value) => typeof value === 'string' && value.split('\\').at(-1) === name);
    }

    function* findNewContainer(entries, before, request, name) {
        const candidates = [];
        for (const entry of entries) {
            if (!entry.id || before.has(entry.id)) {
                continue;
            }
            if (request.keyId) {
                if (entry.id === request.keyId || (yield entry.object.FQCN) === request.keyId) {
                    candidates.push(yield* metadata(entry));
                }
                continue;
            }
            const actualName = yield entry.object.Name;
            const fqcn = yield entry.object.FQCN;
            if (matchesContainerName(name, actualName, fqcn)) {
                candidates.push(yield* metadata(entry));
            }
        }
        if (candidates.length !== 1) {
            report('Идентификация контейнера', { name, keyId: request.keyId, candidates });
            throw new Error('Новый контейнер не определён однозначно. Автоматическое удаление недоступно.');
        }
        return candidates[0];
    }

    function* remove({ info }, expected) {
        const entries = yield* containers(info, 'перед удалением');
        const matches = entries?.filter(({ id }) => id === expected.id);
        const target = matches ? (matches.length === 1 ? matches[0] : null) : yield* containerById(info, expected.id);
        if (!target || target.id !== expected.id) {
            throw new Error('Контейнер для удаления отсутствует или найден неоднозначно.');
        }
        const current = yield* metadata(target);
        if (!['fqcn', 'reader', 'media'].every((field) => current[field] && current[field] === expected[field])) {
            throw new Error('Метаданные контейнера перед удалением изменились или недоступны.');
        }
        yield target.object.propset_Silent(true);
        yield target.object.Delete();
        const after = entries && (yield* containers(info, 'после удаления'));
        const remains = after ? after.some(({ id }) => id === expected.id) : yield* containerById(info, expected.id);
        if (remains) {
            throw new Error('КриптоПро всё ещё видит контейнер после удаления.');
        }
        owned.delete(expected.id);
        report('Удалён контейнер', { id: expected.id });
    }

    return {
        versions: () => run(versions),
        readers: () => run(readers),
        generate: (name, subject, target) => run((context) => generate(context, name, subject, target)),
        remove: ({ id }) => {
            const expected = owned.get(id);
            if (!expected) {
                throw new Error('Контейнер не был создан в этой вкладке.');
            }
            return run((context) => remove(context, expected));
        },
        owned: () => [...owned.values()],
    };
}
