# Cerber – ciężki skaner antywirusowy dla macOS

Cerber to **offline’owy, bardzo dokładny** skaner plików i środowiska systemu. Nie jest to ochrona
w czasie rzeczywistym: to „ciężki agent”, który potrafi długo mielić jeden plik czy folder, rozpakować
go do ostatniej warstwy i porównać każdą warstwę z milionami wzorców.

## Szybki start

```bash
./cerber.sh update                 # pobierz i zbuduj bazy (pierwszy raz ~15–25 min)
./cerber.sh info                   # ile wzorców/sygnatur jest w bazach
./cerber.sh scan ~/Downloads       # skan folderu
./cerber.sh scan plik.dmg --ai     # + analiza „szarej strefy” lokalnym modelem AI
./cerber.sh env                    # skan środowiska (autostart, procesy, sieć, rozszerzenia…)
./cerber.sh full --ai              # środowisko + katalogi użytkownika i aplikacje
./cerber.sh selftest               # test działania na pliku EICAR
./cerber.sh quarantine list        # kwarantanna (restore/delete ID)
```

## Aplikacja (Cerber.app)

`app/build.sh` buduje natywną aplikację `Cerber.app` (SwiftUI) z **pieczęcią integralności** backendu (patrz niżej).
Uruchamiasz ją ręcznie – nic nie działa w tle i nic nie startuje z systemem. Tryby:

| Tryb | Co robi |
|---|---|
| **Przeskanuj laptop** | 4 poziomy: **Szybki** (tylko wzorce, typowe miejsca infekcji + pliki uruchomionych programów), **Średni** (tylko wzorce, cały komputer), **Dokładny** (wszystkie heurystyki + środowisko: autostart, procesy, rozszerzenia, ustawienia bezpieczeństwa, znane ślady najgroźniejszych rodzin malware na macOS + analiza zachowania podejrzanych skryptów), **Mega** (Dokładny + porty, połączenia, ruch sieciowy procesów, zdalny dostęp, logowania, tunele, MDM, logi systemowe (wykrycia XProtect, blokady i obejścia Gatekeepera, logowania SSH, nieudane hasła, nowe elementy w tle), sieć lokalna (ARP spoofing, zabezpieczenie Wi‑Fi), certyfikaty do podsłuchu HTTPS + monitor sieci i zachowania na żywo przez cały skan + AI) |
| **Plik lub folder / Lokalizacja** | przeciągnij albo wybierz – skan dokładny w miejscu, z możliwością kwarantanny |
| **Archiwum w sandboksie** | rozpakowanie w izolacji macOS Seatbelt: bez sieci (także DNS), zapis tylko do katalogu roboczego, reszta dysku niewidoczna, zakaz uruchamiania czegokolwiek poza Pythonem i 7-Zip, limity rozmiaru/plików/czasu (bomby ZIP), usuwanie dowiązań i bitu wykonywania, hasła „infected” itp.; katalog usuwany po skanie |
| **Repozytorium GitHub** | publiczne repo pobierane jako archiwum i skanowane w tym samym sandboksie |
| **Hugging Face** | model / dataset / Space: kod i konfiguracje w całości, wagi pickle (`.bin/.pt/.ckpt/.pkl…`) w całości lub – dla wielu GB – tylko część wykonywalna (`data.pkl` pobierany zapytaniami Range), safetensors/GGUF tylko nagłówki; wykrywa złośliwe pickle, warstwy Lambda w Keras, wstrzyknięcia w szablonach czatu GGUF |
| **Sprawdź link** | link do pobrania: pobranie w sandboksie sieciowym (bez dostępu do Twoich plików), rozpoznanie (przekierowania, IP, certyfikat TLS, listy URLhaus/ThreatFox), jeśli to strona – pobranie wszystkich plików do ściągnięcia (do 20), rozpakowanie archiwów i skan każdego pliku |
| **Ochrona w tle** | (opcja, domyślnie wyłączona) każdy nowo pobrany plik, nowa aplikacja, element autostartu, instalacja .pkg i rozszerzenie przeglądarki jest od razu skanowany jak w poziomie Szybki; złośliwe → kwarantanna + powiadomienie |

Pliki, foldery, repozytoria, Hugging Face i linki są zawsze skanowane dokładnie (bez audytu sieci). AI tylko w poziomie Mega
(w pozostałych trybach – opcjonalny przełącznik). Model AI (Cisco Foundation-Sec 1.1 8B, 4,9 GB) aplikacja pobiera do `models/` dopiero po kliknięciu
„Pobierz model AI” (`python -m cerber.gui_backend ai-install`: wznawiane, weryfikowane SHA-256).

**Mega – sieć i zachowanie na żywo.** Na starcie pełny audyt sieci i zdalnego dostępu. Potem, przez cały skan
(wyszukiwanie, skanowanie, AI), monitor w sandboksie `env` co 5 s porównuje stan z początkowym i ocenia tylko to, co nowe:
połączenia z adresami z list zagrożeń, skrypty/programy bez podpisu na nietypowych portach, regularne „beaconing”
(ten sam program łączy się z tym samym adresem w stałym rytmie), nowe otwarte porty i połączenia przychodzące (ktoś łączy
się z Makiem: SSH, udostępnianie ekranu, narzędzia zdalne), nowe logowania, uruchomione tunele i programy zdalnego
dostępu, nowe procesy (te same heurystyki co w skanie środowiska), nowe elementy autostartu i zmiany w `~/.zshrc` itp.,
zmianę adresu MAC routera (ARP spoofing) i duże wysyłki danych. Nowe pliki (Pobrane, Biurko, /Users/Shared, /tmp)
i programy uruchomione w trakcie trafiają do tego samego skanu. Monitor kończy się razem ze skanem – nic nie zostaje w tle.
Ograniczenia: połączenia krótsze niż ~5 s mogą umknąć, zawartości HTTPS nie widać.

### Analiza zachowania (uruchamianie skryptów w zamkniętym sandboksie)

Skrypty powłoki i Pythona, które skan statyczny uznał za podejrzane lub zaciemnione (do 8 na skan), są uruchamiane na
kilka sekund w profilu `detonate`. Cerber zapisuje, co próbowały zrobić: śledzenie poleceń powłoki (`xtrace`, także
w odkodowanych etapach `base64 | bash`, `eval`), strażnik audytu Pythona (odkodowany kod z `exec`), odmowy jądra z logu
systemowego i sięgnięcia po pliki-przynęty. Rozpoznaje m.in. pobranie i uruchomienie kodu, kradzież haseł/kluczy/portfeli,
wyprowadzanie danych, autostart, fałszywe okno hasła, obchodzenie Gatekeepera, odwróconą powłokę. Odkodowane etapy są
skanowane ponownie, a adresy porównywane z listami zagrożeń. Wynik może tylko podnieść werdykt. Programy (Mach-O, aplikacje)
**nie** są uruchamiane – na prawdziwym Macu to zbyt ryzykowne, a malware i tak wykrywa sandbox.

### Sandbox – każdy skan jest izolowany

| Profil | Używany do | Co wolno |
|---|---|---|
| `strict` | archiwa, repozytoria, Hugging Face, pobrane linki | odczyt tylko systemu, Cerbera i badanego pliku; brak sieci; zapis tylko do woluminu roboczego; uruchomić wolno tylko Pythona i 7-Zip |
| `scan` | pliki/foldery/lokalizacje/cały laptop, ochrona w tle | cały dysk **tylko do odczytu**; brak sieci; uruchomić wolno 7-Zip, UPX i narzędzia Apple do podpisów (codesign/spctl/xattr/mdls) |
| `env` | przegląd środowiska i audyt sieci (Dokładny/Mega) | odczyt; tylko systemowe narzędzia diagnostyczne; brak połączeń z internetem (wyjątek: systemowe odwrotne DNS); `launchctl list`/`kmutil` wykonuje proces nadrzędny i podaje wynik |
| `net` | samo pobieranie (GitHub/HF/link) | internet tak, Twoje pliki nie; nic nie wolno uruchomić |
| `detonate` | **analiza zachowania** podejrzanych skryptów (sh/bash/zsh/Python) | brak sieci (bez wyjątków), brak usług systemowych (mach), fałszywy katalog domowy z przynętami (pęk kluczy, hasła przeglądarek, portfele, klucze SSH), z dysku widać tylko pliki systemowe i interpreter; uruchomić wolno tylko interpreter i narzędzia do przetwarzania tekstu (base64, sed, awk…) – curl, osascript, security, launchctl itd. są blokowane, ale próba jest zapisywana; limit 15 s, CPU, plików, procesów |

Dodatkowe warstwy (gdyby sam sandbox macOS miał lukę):
1. katalog roboczy to osobny wolumin (obraz dysku) zamontowany `noexec,nosuid,nodev` – jądro nie uruchomi z niego niczego, a jego rozmiar ogranicza bomby ZIP;
2. **samosprawdzenie** przed każdym skanem: proces w sandboksie próbuje zapisu poza sandboksem, połączenia sieciowego, uruchomienia powłoki i pliku z katalogu roboczego, prośby o uprawnienia (TCC), dostępu do schowka, ekranu, AppleEvents, okien autoryzacji, pęku kluczy i Twoich plików – jeśli cokolwiek się uda, skan jest przerywany;
3. w każdym profilu zablokowane: prośby o uprawnienia, AppleEvents, schowek, WindowServer, kamera/mikrofon/lokalizacja, kontakty/kalendarz/zdjęcia, okna autoryzacji, pęk kluczy, rejestrowanie zadań launchd;
4. „strażnik” Pythona (audit hook) w procesie skanującym blokuje nieoczekiwane uruchamianie programów, połączenia i ładowanie bibliotek;
5. limity zasobów (czas CPU, rozmiar pliku, deskryptory, brak zrzutów pamięci), osobna sesja procesów, wszystkie procesy powstałe w sandboksie są śledzone i zabijane po zakończeniu;
6. proces nadrzędny traktuje wszystko z sandboksa jako niezaufane dane: limit rozmiaru zdarzeń, do aplikacji trafiają tylko zdarzenia z listy dozwolonych (log, etap, postęp, znalezisko, błąd, naruszenie sandboksa; z monitora sieci – oczyszczone zdarzenia sieciowe), ścieżki raportów tylko z folderu `reports/`, kwarantanna tylko dla plików ze skanowanych lokalizacji.

### Pieczęć integralności (Cerber.app)

Cerber.app ma **Pełny dostęp do dysku** i przekazuje go każdemu procesowi, który uruchamia – a backend to zwykły Python
w folderach, do których może pisać każdy program działający na Twoim koncie. Gdyby ktoś podmienił jeden plik, dostałby
cały dysk. Dlatego `app/build.sh` „pieczętuje” backend (`cerber/integrity.py`):

* prekompiluje pliki `.pyc` do wnętrza aplikacji (`Contents/Resources/pycache`) – backend nie czyta ich z folderów
  `__pycache__`, a katalogu projektu nie ma na ścieżce importu (`.venv/cerber-path` zawiera tylko dowiązanie do `cerber/`);
* zapisuje manifest (`Contents/Resources/backend.manifest`) z SHA-256 każdego pliku, który backend uruchamia albo wczytuje:
  `cerber/`, `rules/`, `.venv`, interpreter Pythona z biblioteką standardową i bibliotekami z Homebrew, narzędzia
  (7-Zip, UPX, llama-server, libimobiledevice), `app/mock_backend.py` i bazy `db/compiled/clamav/*.pkl` oraz
  `db/compiled/yara.bin` (wczytanie podmienionej bazy jest tak samo groźne jak podmieniony kod);
* skrót manifestu wkompilowuje w plik wykonywalny (sekcja `__TEXT,__cerber_seal`), więc obejmuje go podpis aplikacji.

Przed uruchomieniem każdego procesu Pythona aplikacja liczy manifest od nowa. Przy jakiejkolwiek różnicy **nie uruchamia
silnika** i pokazuje okno „Cerber zablokował uruchomienie swojego silnika” z listą zmienionych plików. Bazy SQLite
(hashe, IOC) to dane, nie kod – nie są pieczętowane; bazy ClamAV wczytuje dodatkowo ograniczony unpickler, który zna
tylko listy, krotki, słowniki i tablice liczb – nigdy kod.

* **Po `./cerber.sh update`** zmieniają się bazy w `db/compiled` (sygnatury ClamAV, skompilowane reguły YARA). Przy
  następnym skanie aplikacja pokaże okno z listą zmian („w tym bazy sygnatur: N”) i przyciskiem **Zatwierdź obecny stan…** –
  macOS poprosi o **hasło administratora**. Nowy skrót trafia do pliku należącego do roota
  (`/Library/Application Support/Cerber/backend.seal`, ważnego tylko dla tej kompilacji aplikacji), a manifest do
  `~/Library/Application Support/Cerber/backend.manifest` – malware działające na Twoim koncie nie podrobi takiego
  zatwierdzenia. Zatwierdzaj tylko zmiany, które zrobiłeś sam (aktualizacja baz, edycja kodu, `pip install`). Jeśli niczego
  nie zmieniałeś, **nie zatwierdzaj**: przeskanuj komputer i przebuduj aplikację. Przebudowa (`app/build.sh`) zamiast
  zatwierdzania też jest w porządku.
* **`brew upgrade`** Pythona (`python@3.14`) albo którejkolwiek z pieczętowanych paczek Homebrew – bibliotek, z których
  korzysta Python (`openssl@3`, `xz`, `zstd`, `sqlite`, `mpdecimal`), oraz `sevenzip`, `upx`, `llama.cpp` (z `ggml`
  i `libomp`) i – jeśli jest zainstalowany – `libimobiledevice` z zależnościami – przenosi pliki do nowych ścieżek
  z numerem wersji w `/opt/homebrew/Cellar`. Takiej zmiany nie da się zatwierdzić w aplikacji: **przebuduj ją**
  (`app/build.sh`). Dokładną listę pokazują wiersze `T`/`F`/`L` na początku `Cerber.app/Contents/Resources/backend.manifest`.
* **Każda przebudowa wymaga ponownego nadania Pełnego dostępu do dysku.** Aplikacja jest podpisywana ad hoc, więc po
  każdym `app/build.sh` ma nowy podpis i macOS traktuje ją jak inny program: w **Ustawienia systemowe → Prywatność
  i ochrona → Pełny dostęp do dysku** usuń stary wpis Cerbera (−) i dodaj nową `Cerber.app` (+).

Przełączniki `app/build.sh`:

| Zmienna | Działanie |
|---|---|
| `CERBER_BUNDLE=/ścieżka/Cerber.app` | buduje aplikację w innym miejscu (np. w folderze tymczasowym). Pieczęć dalej wskazuje ten projekt: taka kopia uruchamia wyłącznie backend z katalogu, dla którego ją zbudowano |
| `CERBER_NO_SEAL=1` | kompilacja deweloperska **bez pieczęci**: backend nie jest sprawdzany, działa `CERBER_ROOT`, `--selftest-parse` wykonuje też test atrapy API z katalogu tymczasowego (w zapieczętowanej kompilacji jest pomijany). Nigdy do codziennego używania z Pełnym dostępem do dysku |
| `CERBER_DEBUG=1` | kompilacja bez optymalizacji (szybsza) |

### API na localhost

W aplikacji: **Integracje → API (localhost)** (domyślnie wyłączone; działa tylko, gdy aplikacja jest otwarta). Ręcznie:
`CERBER_API_TOKEN=… .venv/bin/python -m cerber.api_server --port 8765`. Wszystko, co robi aplikacja, jest dostępne przez
HTTP: `/api/info`, `/api/scan`, `/api/sandbox` (+ `/api/sandbox/upload`), `/api/github`, `/api/huggingface`, `/api/url`,
`/api/laptop`, `/api/quarantine`, `/api/history`, `/api/ai-install`, zadania `/api/jobs/{id}` ze strumieniem zdarzeń (NDJSON lub SSE),
anulowaniem i raportem. Dokumentacja z przykładami `curl`: `http://127.0.0.1:8765/`. Zabezpieczenia: tylko 127.0.0.1, token wymagany
w każdym zapytaniu, ochrona przed DNS rebinding (nagłówek Host), brak CORS i odrzucanie zapytań z innych stron (Origin /
Sec-Fetch-Site), tylko JSON (bez formularzy), skany i tak idą przez ten sam sandbox.

Backend aplikacji to `python -m cerber.gui_backend` (protokół JSON Lines: `app/PROTOCOL.md`); raporty zapisuje jako `reports/gui-*.html/json`.
Debugowanie bez izolacji: `CERBER_NO_SANDBOX=1` (sandbox) / `CERBER_NO_NOEXEC=1` (bez woluminu noexec).

Raporty JSON + HTML trafiają do `reports/`. Kod wyjścia: 2 = znaleziono złośliwe, 1 = podejrzane, 0 = czysto.

Ważniejsze opcje skanu: `--fast` (bez TLSH), `--workers N`, `--quarantine` (przenosi ZŁOŚLIWE pliki
do zaszyfrowanej kwarantanny), `--exclude GLOB`, `--timeout S` (na plik), `--max-size MB`,
`--include-system` (także zapieczętowany wolumin `/System`), `--ai-all`.

## Co jest w środku

| Warstwa | Co robi |
|---|---|
| **Hashe** | MD5/SHA1/SHA256 każdego obiektu vs ClamAV (.hdb/.hsb), **MalwareBazaar** (pełny zrzut), signature-base; hashe sekcji PE (ClamAV .mdb, ~2,7 mln); biała lista ClamAV (.fp) |
| **Sygnatury ClamAV** | własny silnik dla ~428 tys. sygnatur bajtowych (.ndb) i logicznych (.ldb): wildcardy `?? a? * {n-m} (a\|b) !(..) [n-m] (B)(L)`, offsety `EP+n, Sx+n, SL, SE, EOF-n, n,m`, modyfikatory `::i ::w ::a ::f`, wyrażenia `0&1&(2\|3)>2,1`, PCRE, ograniczenia `FileSize/EntryPoint/NumberOfSections/Container`; prefiltr Aho-Corasick (Rust) na ~1,1 mln kotwic, leniwa weryfikacja regexami |
| **YARA** | ~13,4 tys. reguł w poziomach zaufania: **XProtect Apple** (pewne), **YARA-Forge core** (pewne przy wysokim score), własne paczki Cerbera `rules/custom/` (312 reguł skrypty/web + 59 macOS, 0 fałszywych alarmów na czystych plikach), **community** (YARA-Forge full, Elastic macOS, `rules/experimental/`) – tylko wskazówki, nigdy samodzielny werdykt „złośliwy”; wadliwe reguły wycinane bisekcją |
| **IOC** | URLhaus + ThreatFox: URL/domeny/IP wyciągnięte z plików porównywane z listami złośliwych |
| **Podobieństwo** | TLSH plików wykonywalnych vs ~1 mln próbek MalwareBazaar – tylko dowód wspierający (infektory plików i binarki Go/Rust są „podobne” do legalnych plików) |
| **Rozpakowywanie** | ~30 formatów: zip/jar/apk/crx/ooxml, **Electron .asar**, tar.*, gz/bz2/xz/zstd/lz4/lzip, 7z, rar, cab, iso, **dmg**, **pkg** (Payload, skrypty pre/postinstall, InstallerJS), cpio, pbzx, deb, rpm, wim, vhd, chm, msi, NSIS/SFX, e-maile; hasła „infected” itp.; ochrona przed bombami |
| **Pliki wykonywalne** | PE (packery, entropia, importy/API, zasoby, nakładki, .NET, PyInstaller), ELF, **Mach-O** (podpis kodu, ad-hoc, hardened runtime, entitlements, dyliby, UPX), plastry fat, `codesign`/`spctl`/kwarantanna/źródło pobrania |
| **Dokumenty** | VBA (własna dekompresja MS-OVBA, stomping p-code), XLM 4.0, DDE, zdalne szablony, Follina, OLE/Equation Editor, RTF, PDF (JS, strumienie, ObjStm, szyfrowanie), LNK, OneNote |
| **Skrypty** | deobfuskacja warstwowa (base64/-EncodedCommand, char-code, konkatenacje, gzip, obfuscator.io, Dean Edwards, VBE, skompilowany AppleScript .scpt/JXA) i heurystyki: PowerShell, JS, VBS, batch, shell, Python, npm, AppleScript, PHP/Perl/Ruby, HTML/HTA (smuggling, ClickFix), .reg, skróty |
| **Środowisko macOS** | LaunchAgents/Daemons, elementy logowania, cron, pliki rc powłoki, profile, rozszerzenia systemu i przeglądarek, procesy (podpisy, łańcuchy osascript), sieć, hosts/DNS/proxy, SIP/Gatekeeper/FileVault/firewall/XProtect; znalezione pliki idą do głębokiego skanu |
| **AI (lokalnie)** | Cisco Foundation-Sec 1.1 8B Instruct (Llama 3.1 8B douczony na tekstach o bezpieczeństwie, GGUF Q4_K_M przez llama-server) **weryfikuje zarzuty** silników wobec plików z „szarej strefy”: każdy zarzut ocenia jako trafny / chybiony / niepewny z pewnością i uzasadnieniem cytującym plik, oraz mówi, czy to podejrzewana rodzina, podobna, inna, czy legalny program. Nie decyduje: przesuwa punkty zarzutów (chybiony −50 %, trafny +20 %), łącznie najwyżej ±15 pkt; nigdy nie rusza sygnatur/hashy/ClamAV/IOC, nie robi z pliku CZYSTEGO (odporność na prompt injection: dwa przebiegi w odwrotnej kolejności, cytaty sprawdzane w pliku) |
| **Kalibracja** | przy `update` Cerber skanuje ~25 tys. czystych plików systemowych Apple i ~45 tys. plików z notaryzowanych aplikacji; reguły, które tam strzelają, są wyłączane (z aplikacji firm trzecich – tylko reguły community) |

Werdykt liczony jest **per jednostka** (plik/członek archiwum + jego zdekodowane warstwy + kontenery nad nim), więc słabe,
niepowiązane sygnały z tysięcy plików w dużej paczce (np. `app.asar`) się nie sumują.

Werdykty: `ZŁOŚLIWY` (dokładne trafienie sygnatury lub silna heurystyka), `NIECHCIANY (PUA)` (adware,
narzędzia hakerskie), `PODEJRZANY`, `INFO`, `CZYSTY`.

### Najgroźniejsze rodziny macOS (2023–2026)

Oprócz XProtect, YARA-Forge, ClamAV i MalwareBazaar Cerber ma własne, ręcznie sprawdzone wskaźniki dla rodzin,
które w raportach SentinelOne, Jamf, Elastic, Microsoft, Huntress, Moonlock, Kandji/Iru, Unit 42, ESET i Objective-See
pojawiają się najczęściej:

* **Reguły YARA** (`rules/custom/macos.yar`, sekcja „TOP macOS FAMILIES”): AMOS + jego backdoor, Banshee, Poseidon/Odyssey,
  Cuckoo, Cthulhu, MacSync, KandyKorn/SUGARLOADER, Hidden Risk, NimDoor, FlexibleFerret, BeaverTail/InvisibleFerret,
  RustDoor, TodoSwift, ChillyHell, PasivRobber, ZuRu, XCSSET, LightSpy, SpectralBlur, JokerSpy, CloudMensis, ObjCShellz,
  ransomware Turtle. Każda reguła ma bezpieczny plik testowy w `tests/samples/yara/macos/` (same ciągi znaków, bez kodu).
* **Reguły Elastic** (`protections-artifacts`, tylko macOS, licencja Elastic License 2.0 – tekst zapisywany obok reguł
  w `db/yara/elastic/`): poziom community, czyli wskazówka, nigdy samodzielny werdykt, i podlegają kalibracji
  `fp_disabled.json`. Same reguły YARA przebudujesz bez pobierania dużych baz: `.venv/bin/python -m cerber.updater yara --offline`.
* **Znane artefakty** (`cerber/envscan/artifacts.py`, poziomy Dokładny i Mega): dokładne ścieżki, ukryte foldery,
  etykiety LaunchAgent/LaunchDaemon, identyfikatory aplikacji i nazwy procesów tych rodzin. Tylko `lstat`/`listdir`
  kilku stałych miejsc (bez rekurencji, ~0,1 s). Artefakt unikalny dla rodziny = „złośliwy”, nazwy ogólne
  (np. `~/.pass`, `/tmp/out.zip`) liczą się tylko razem z mocnym śladem tej samej rodziny; każdy trafiony plik
  trafia do głębokiego skanu.

Nowe warianty, które zmieniają ścieżki i szyfrują ciągi znaków, wykryją dopiero heurystyki (AppleScript z wyłudzaniem
hasła, `dscl -authonly`, archiwizacja pęku kluczy, ClickFix, persystencja) i AI – nie same sygnatury.

## Struktura

```
cerber/core.py, pipeline.py, verdict.py   model danych, rekurencyjny potok, werdykt
cerber/engines/                           hash, clamav(_db,_sig), yara_engine, ioc_fuzzy, ai
cerber/analyzers/                         wtyczki: archiwa, dokumenty, pliki wykonywalne, skrypty, IOC…
cerber/deobf/                             biblioteka deobfuskacji
cerber/envscan/                           skaner środowiska macOS
cerber/llm/                               silnik LLM (z LocalCode)
cerber/scanner.py, cli.py, report.py      orkiestracja (fork + gc.freeze), CLI, raporty
rules/custom/                             własne reguły YARA
db/                                       bazy (generowane przez `update`)
```

Testy: `.venv/bin/python tests/run_all.py [--quick]` – analizatory, 62 testy jednostkowe, werdykty próbek, paczki YARA,
test „round-trip” silnika ClamAV (z tysięcy sygnatur generowane są bufory, które muszą zostać wykryte), EICAR przez wszystkie silniki.

Narzędzia deweloperskie: `python -m cerber.devtool PLIK` (drzewo obiektów i wykryć bez baz),
`python -m cerber.tools.yaracheck REGUŁY.yar` (kompilacja + test fałszywych alarmów),
`python -m cerber.envscan` (sam skaner środowiska).

## Ograniczenia (uczciwie)

* Żaden skaner nie wykrywa 100% zagrożeń — nowe, nieznane próbki łapią tylko heurystyki i AI.
* Bez roota / Full Disk Access część środowiska (BTM, cron innych użytkowników, TCC.db) nie jest sprawdzana — raport to wypisuje.
* ClamAV bytecode (.cbc), sygnatury ikon i porównania bajtów w .ldb nie są obsługiwane (~0,1% sygnatur).
* Pliki i foldery trzymane **tylko w iCloud Drive / innej chmurze** (placeholdery przy „Optymalizuj miejsce na Macu”) są pomijane i liczone w raporcie — samo ich otwarcie kazałoby macOS pobrać je z chmury (cały skan by się wlókł i ściągnął całą chmurę). Nie ma ich na dysku, więc nie mogą się uruchomić; po pobraniu na Maca kolejny skan je sprawdzi.
