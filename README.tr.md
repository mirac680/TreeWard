# TreeWard

**Git deposunu yayımlamadan önce çalışan, yerel ve gizlilik odaklı bir ön kontrol.**

TreeWard; yanlışlıkla eklenmiş olabilecek kimlik bilgilerini, özel anahtar izlerini, hassas dosya adlarını ve büyük dosyaları arar. README ve lisans dosyalarının varlığını da kontrol eder. Bilgisayarınızda çalışır, çalışma zamanı bağımlılığı yoktur ve eşleşen gizli değeri rapora yazmaz.

> TreeWard hızlı bir ön kontroldür; kapsamlı bir güvenlik denetimi değildir ve Git indeksini veya geçmişini taramaz.

## Hızlı başlangıç

Bu projenin kopyasında:

~~~console
python -m pip install .
treeward .
~~~

Komut satırı aracını kurmadan:

~~~console
python -m treeward .
~~~

Depo içindeki herhangi bir klasörden çalıştırabilirsiniz. TreeWard Git kökünü bulur; Git tarafından izlenen ve ignore edilmemiş izlenmeyen dosyaları tarar.

## Örnekler

~~~console
treeward
treeward . --format json
treeward . --format sarif --output treeward.sarif
treeward . --fail-on medium
treeward . --max-file-size-mb 10
~~~

<code>--format</code> seçenekleri <code>text</code>, <code>json</code> ve <code>sarif</code> değerleridir. Varsayılan biçim <code>text</code>, varsayılan CI eşiği <code>high</code> değeridir. <code>--fail-on</code> için <code>high</code>, <code>medium</code>, <code>low</code> veya <code>never</code> seçilebilir. AWS erişim anahtarı kimliği tek başına gizli bir kimlik bilgisi olmadığı için orta önem düzeyinde raporlanır.

## Ayarlar

Depo kökünde <code>.treeward.toml</code> oluşturabilirsiniz:

~~~toml
[scan]
max_file_size_mb = 2
exclude = ["docs/generated/**"]
fail_on = "high"
~~~

Hariç tutulan dosyalar okunmaz ve README/lisans denetimlerine dahil edilmez. Gerçek bir bulguyu gizleyebileceği için geniş kapsamlı hariç tutmalardan kaçının.

## Kapsam ve sınırlar

- Mevcut çalışma ağacındaki izlenen ve ignore edilmemiş izlenmeyen dosyaları tarar.
- Git indeksini ayrı olarak incelemez; sahnelenen içerik mevcut dosyadan farklıysa bu sürüm kontrol edilmez.
- Git geçmişini taramaz; daha önce silinmiş bir sır eski commit’lerde kalmış olabilir.
- Sembolik bağlantıları, ikili dosyaları, okunamayan dosyaları ve boyut sınırını aşan dosyaları atlar.
- Yalnızca UTF-8 metnini denetler; bulduğu kimlik bilgisinin hâlâ etkin olup olmadığını doğrulamaz.
- Temiz rapor, deponun yayımlanmaya kesinlikle güvenli olduğunu kanıtlamaz.

Daha geniş kapsam için Git sağlayıcınızın gizli bilgi taramasını ve geçmişi tarayabilen özel bir aracı da kullanın.

## Lisans

MIT Lisansı. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
