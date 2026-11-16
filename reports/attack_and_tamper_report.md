# Звіт Issue #38 — Базовий модуль атаки та перевірка цілісності архіву

## 1. Криптоаналіз слабких шифрів генетичним алгоритмом за частотами n-грам

| Шифр | Справжній ключ | Відновлений ключ | Точність відновлення тексту |
|---|---|---|---:|
| Віженер (EN) | `KEY` | `KEY` | 100.0% |
| Віженер (UA, корпус) | `КЛЮЧ` | `КЛЮЧ` | 100.0% |
| Підстановка (EN) | `QWERTYUIOPASDFGHJKLZXCVBNM` | `QWERTYUIOPMSDFGHBKLZXCVANJ` | 99.4% |
| Короткий XOR (EN) | `SARC` | `SARC` (`0x53415243`) | 100.0% |

## 2. Аудит цілісності чужого архіву (`team/reference/ref_01_single_file.arc`)

| Модифікація байтів | Очікуваний код | Отриманий код | Чистий каталог виводу | Статус |
|---|---|---|---|---|
| Flip byte in VolumeHeader nonce (offset 25) | `E_HMAC` | `E_HMAC` | ТАК | OK |
| Flip byte in Ciphertext (offset 0) | `E_HMAC` | `E_HMAC` | ТАК | OK |
| Flip byte in HMAC-SHA256 tag (last byte) | `E_HMAC` | `E_HMAC` | ТАК | OK |
| Truncate archive by 5 bytes | `E_LENGTH` | `E_LENGTH` | ТАК | OK |
| Truncate archive below 73 bytes | `E_SHORT` | `E_SHORT` | ТАК | OK |
| Corrupt MAGIC header | `E_MAGIC` | `E_MAGIC` | ТАК | OK |
