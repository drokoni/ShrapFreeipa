# ShrapFreeipa
Клонирование и сборка экспортера данных FreeIPA для BloodHound.

🚀 Установка Rust
1. Установите Rust через rustup (рекомендуемый способ):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh 
```
2. Следуйте подсказкам установщика (по умолчанию ставится toolchain stable).

3. Добавьте в текущую сессию переменные окружения:
```bash
source $HOME/.cargo/env
```
Обновите до последней стабильной версии (необязательно):
```bash
rustup update stable
```
📥 Клонирование проекта
```bash
git clone git@github.com:drokoni/ShrapFreeipa.git
cd ShrapFreeipa
```
🛠 Сборка

Сборка в режиме разработки:
```bash
cargo build
```
Сборка оптимизированного релиза:
```bash
cargo build --release
```
После успешной сборки бинарник будет находиться в:
```bash
target/release/kurs04
```
▶️ Запуск

Параметры запуска можно посмотреть через флаг --help:
```bash
./target/release/kurs04 --help
```
