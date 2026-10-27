# Komponenty zewnętrzne / Third-party components

To repozytorium **nie zawiera** cudzych baz, reguł ani modeli. Cerber pobiera je dopiero na komputerze użytkownika
(`./cerber.sh update`, model AI – po kliknięciu w aplikacji). Nie są objęte licencją Cerbera (`LICENSE`, pkt 7) –
obowiązują ich własne licencje, a użytkownik musi ich przestrzegać.

This repository does **not** contain third-party databases, rules or models. Cerber downloads them on the user's
computer. They are not covered by the Cerber License and remain under their own licenses.

| Źródło / Source | Co / What | Licencja / License (wg źródła) |
|---|---|---|
| [ClamAV](https://www.clamav.net/) (Cisco Talos) | sygnatury `main/daily/bytecode.cvd` | zob. ClamAV |
| [abuse.ch](https://abuse.ch/) MalwareBazaar, ThreatFox, URLhaus | hashe, IOC, adresy URL | zob. abuse.ch terms |
| [YARA-Forge](https://github.com/YARAHQ/yara-forge) | reguły YARA (agregat) | licencje poszczególnych reguł |
| [signature-base](https://github.com/Neo23x0/signature-base) | reguły YARA, IOC | Detection Rule License 1.1 |
| [Elastic protections-artifacts](https://github.com/elastic/protections-artifacts) | reguły YARA (macOS) | Elastic License 2.0 |
| [ESET malware-ioc](https://github.com/eset/malware-ioc) | IOC, reguły YARA | BSD-2-Clause |
| Repozytoria reguł YARA wymienione w `cerber/feeds_macos_yara.py` | reguły YARA (macOS) | licencja podana przy każdym repozytorium |
| [AlienVault OTX](https://otx.alienvault.com/) (opcjonalnie, własny klucz) | IOC | zob. OTX terms |
| [CIRCL MISP OSINT feed](https://www.circl.lu/doc/misp/feed-osint/) | IOC | zob. CIRCL |
| [MVT indicators](https://github.com/mvt-project/mvt-indicators) | wskaźniki iOS | MIT |
| [Amnesty Tech investigations](https://github.com/AmnestyTech/investigations) | wskaźniki iOS | CC BY |
| [Echap stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | wskaźniki stalkerware | CC BY 4.0 |
| [Citizen Lab malware-indicators](https://github.com/citizenlab/malware-indicators) | wskaźniki NSO | CC BY-NC-SA 4.0 (tylko niekomercyjnie) |
| [Cisco Foundation-Sec 1.1 8B Instruct](https://huggingface.co/fdtn-ai) (GGUF) | model AI weryfikujący zarzuty | licencja modelu (zob. Hugging Face) |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | uruchamianie modelu (`llama-server`) | MIT |

Biblioteki Pythona (np. `yara-python`) instalowane przez `pip` mają własne licencje – zob. ich strony w PyPI.
Python libraries installed with `pip` keep their own licenses.
