# Участие в разработке

## 🌐 Добавить сайт

Откройте [issue «Добавить сайт»](https://github.com/Nettrove/no-mintsifra/issues/new?template=site.yml) и укажите домен. Бот сам проверит, на чьём сертификате работает сайт, и добавит его в список, если сертификат выдан Минцифры.

## 🐞 Сообщить об ошибке

Откройте [issue «Ошибка»](https://github.com/Nettrove/no-mintsifra/issues/new?template=bug.yml) и приложите отчёт, который сохраняет команда

```
"%LocalAppData%\no-mintsifra\no-mintsifra.exe" doctor --report
```

Отчёт сохраняется в «Документы» как `no-mintsifra-report.txt`. Содержимое трафика в него не попадает, а путь к профилю заменён на `%USERPROFILE%`.

## 📝 Коммиты

История ведётся по [Conventional Commits](https://www.conventionalcommits.org/ru/), в качестве scope берётся имя пакета или области: `proxy`, `localca`, `russianca`, `pins`, `pinbot`, `probe`, `update`, `sysproxy`, `rootstore`, `trust`, `serve`, `cli`, `install`, `catalog`, `snapshot`, `readme`, `docs`, `ci`, `build`.

```
fix(sysproxy): keep the user's manual proxy for uncovered hosts

With AutoConfigURL set, WinINet and Chromium ignore ProxyServer, so
users of v2rayN or Clash in system-proxy mode silently lost their
proxy for all other traffic after install.

The PAC now falls back to the current ProxyServer and honours
ProxyOverride instead of returning DIRECT.

Fixes #12
Co-Authored-By: Claude <noreply@anthropic.com>
```

- **Тема:** до 72 символов, повелительное наклонение (`add`, а не `added`), без точки.
- **Тело:** после пустой строки, перенос на 72 символах. Объясняет, зачем понадобилось изменение и что было не так. Что изменилось, видно из диффа.
- **Трейлеры:** одним блоком в конце: `Fixes #N`, `Co-Authored-By:`, `BREAKING CHANGE:`.
- **Язык:** английский, как код и комментарии. Русский текст для людей идёт в описание релиза.
- **Типы:** `feat`, `fix`, `refactor` (поведение не меняется), `perf`, `test`, `docs`, `ci`, `build`, `chore`.

Исправления безопасности оформляются как обычный `fix`, без слов «уязвимость» и «эксплойт», пока не опубликован advisory.

Тема коммита проверяется в CI при каждом push.

## ✂️ Нарезка

- Один коммит: одно логическое изменение. Если в теме хочется написать «and», это, скорее всего, два коммита.
- Каждый коммит собирается и проходит тесты, чтобы работал `git bisect`.
- Рефакторинг и смена поведения идут разными коммитами: сначала `refactor` без единого изменения логики, затем маленький `fix` или `feat`.
- Тест лежит в том же коммите, что и исправление.
- Чистое форматирование (`gofmt`, переносы) идёт отдельным коммитом.
- Список сайтов `pins.json` правит только бот и только в ветке `pins`. Встроенный снимок в `main` обновляется отдельным коммитом `chore(snapshot): refresh embedded pin set`.
- Смена формата данных идёт отдельным коммитом с `BREAKING CHANGE:`.
- В итоговой истории нет `wip`, `fix previous commit` и подобного.

## 🔧 Рабочий процесс

Разработка ведётся прямо в `main`, история линейная, без merge-коммитов.

```bash
git config commit.template .gitmessage

git add -p                 # добавлять кусками, а не файл целиком
git commit -v              # дифф виден прямо в редакторе сообщения

# нашли ошибку в коммите, сделанном три коммита назад:
git commit --fixup=<sha>
git rebase -i --autosquash origin/main

git push
```

Пока коммиты не отправлены, их можно переписывать как угодно. Отправленную историю `main` не переписывайте.

Коммиты и теги подписываются SSH-ключом:

```bash
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config commit.gpgsign true
git config tag.gpgsign true
```

Релизный тег создаётся подписанным, а его текст становится русским вступлением к описанию релиза:

```bash
git tag -s v1.0.0-beta -m "Короткое описание релиза для людей"
```

Не отмечайте релиз как pre-release, даже бету: программа узнаёт о новых версиях через последний релиз (`/releases/latest`), а pre-release туда не попадает. Порядок версий: `v1.0.0-beta` < `v1.0.0-beta.2` < `v1.0.0`.

## ✅ Проверки перед push

```bash
gofmt -l .
go vet ./...
go test ./...
```

CI дополнительно запускает тесты с `-race`, `staticcheck` и `govulncheck`.
