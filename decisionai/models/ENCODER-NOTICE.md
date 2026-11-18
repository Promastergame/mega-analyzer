# Весовые файлы Transformer-энкодера

| Файл | Что это | Происхождение |
| --- | --- | --- |
| `encoder-tiny.dte` | BERT-энкодер 3 слоя · 12 голов · d=312, WordPiece 83 828 токенов; таблица слов в int8 (по строке — масштаб), остальное float32 | [`cointegrated/rubert-tiny2`](https://huggingface.co/cointegrated/rubert-tiny2), лицензия **MIT** (автор — David Dale). Конвертация: `scripts/convert_encoder.py` |
| `nli-tiny.dte` | Тот же энкодер, дообученный как NLI cross-encoder (entailment / neutral / contradiction); слова и словарь берутся из `encoder-tiny.dte` (были заморожены) | Дообучение: `scripts/train/train_nli.py`, конвертация: `scripts/convert_nli.py` |
| `s1-distilled.dte` | v1.14 (с v1.13): BERT 3 слоя · d=312, **основа — [`sergeyzh/rubert-tiny-turbo`](https://huggingface.co/sergeyzh/rubert-tiny-turbo)** (MIT, автор — `sergeyzh` на Hugging Face; дообучение rubert-tiny2 под эмбеддинги предложений). Своя таблица слов (int8 по строкам, заморожена), 3 слоя дообучены под решения «state + вопрос» на данных проекта + перефразах вопросов (`data/distill/paraphrases.json`) | Дистилляция: `scripts/distill/train_embed.py` (`INIT=hf`); мягкие метки учителей Jev (TypeSafe, через OpenRouter) и [`MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7`](https://huggingface.co/MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7) (MIT); v1.14: + мягкие метки учителя EmbeddingGemma 2 + адаптер на 1 068 новых кейсах (`data/distill/syn5/syn6.gemma.plans.jsonl`) |
| `s1-v113-b.dte` | v1.13: бывший второй участник ансамбля (от `rubert-tiny-turbo`, без перефразов). С v1.14 не грузится автоматически (ансамбль больше не помогает); включить: `-distilled models/s1-distilled.dte,models/s1-v113-b.dte`. Таблицы слов в файле нет — берётся у первой модели | то же |
| `gemma-head.pt` | v1.14: адаптер (0,9 млн параметров, PyTorch) поверх замороженной [`google/embeddinggemma-2`](https://huggingface.co/google/embeddinggemma-2) — офлайн-учитель для дистилляции. Весов Gemma в проекте нет | `scripts/distill/gemma_cache.py` + `train_gemma_head.py`; EmbeddingGemma 2 — Google DeepMind, **Apache 2.0** (+ [Gemma Prohibited Use Policy](https://ai.google.dev/gemma/prohibited_use_policy)) |

Данные дообучения `nli-tiny.dte` (воспроизводятся скриптами из `scripts/train/`):

* [`cointegrated/nli-rus-translated-v2021`](https://huggingface.co/datasets/cointegrated/nli-rus-translated-v2021) — русские переводы SNLI / MNLI / SICK / FEVER-NLI / ANLI и др. **Автор датасета не указал лицензию**; исходные корпуса — открытые академические, но их условия наследуются. Если нужна юридическая чистота, переобучите модель на данных с понятной лицензией (`train_nli.py` принимает любые пары в том же формате).
* [`stanfordnlp/snli`](https://huggingface.co/datasets/stanfordnlp/snli) — CC BY-SA 4.0.
* синтетические доменные пары `scripts/train/gen_domain_nli.py` (проект).

Веса — это **не** LLM и не «знания о мире»: у модели 29 млн параметров, она хорошо различает полярность и тематику коротких утверждений, но ошибается на редких оборотах, числах, длинных текстах. Модель не подписана — загружайте только доверенные файлы (формат парсится с проверкой границ, исполняемого кода в нём нет).
