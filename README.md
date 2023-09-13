# Zeek-Parser-SSDP

English is [here](https://github.com/nttcom/zeek-parser-SSDP/blob/main/README_en.md)

## 概要

Zeek-Parser-SSDPとはSSDPを解析できるZeekプラグインです。

## 使い方

### マニュアルインストール

本プラグインを利用する前に、Zeek, Spicyがインストールされていることを確認します。
```
# Zeekのチェック
~$ zeek -version
zeek version 5.0.0

# Spicyのチェック
~$ spicyz -version
1.3.16
~$ spicyc -version
spicyc v1.5.0 (d0bc6053)

# 本マニュアルではZeekのパスが以下であることを前提としています。
~$ which zeek
/usr/local/zeek/bin/zeek
```

本リポジトリをローカル環境に `git clone` します。
```
~$ git clone https://github.com/nttcom/zeek-parser-SSDP.git
```

ソースコードをコンパイルして、オブジェクトファイルを以下のパスにコピーします。
```
~$ cd ~/zeek-parser-SSDP/analyzer
~$ spicyz -o ssdp.hlto ssdp.spicy ssdp.evt
# ssdp.hltoが生成されます
~$ cp ssdp.hlto /usr/local/zeek/lib/zeek-spicy/modules/
```

同様にZeekファイルを以下のパスにコピーします。
```
~$ cd ~/zeek-parser-SSDP/scripts/
~$ cp main.zeek /usr/local/zeek/share/zeek/site/
```

最後にZeekプラグインをインポートします。
```
~$ tail /usr/local/zeek/share/zeek/site/local.zeek
...省略...
@load SSDP
```

本プラグインを使うことで `ssdp.log` が生成されます。
```
~$ cd ~/zeek-parser-SSDP/testing/Traces
~$ zeek -Cr test.pcap /usr/local/zeek/share/zeek/site/main.zeek
```

## ログのタイプと説明
本プラグインはssdpの全ての関数を監視して`ssdp.log`として出力します。

| フィールド | タイプ | 説明 |
| --- | --- | --- |
| ts | time | 通信した時のタイムスタンプ |
| SrcIP | addr | 送信元IPアドレス  |
| SrcMAC | string | 送信元macアドレス |
| Method | string | リクエストメソッドに関する情報 |
| SERVER_or_USER_AGENT | string | デバイスやサービスの識別情報や詳細なバージョン情報 |


`ssdp.log` の例は以下のとおりです。
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssdp
#open	2023-09-13-04-35-24
#fields	ts	SrcIP	SrcMAC	Method	SERVER_or_USER_AGENT
#types	time	addr	string	string	string
1668040655.960467	192.168.1.131	dc:72:23:56:9a:d1	NOTIFY	Linux/4.14.76+ UPnP/1.0 CyberLinkJava/1.8
1668040683.179186	192.168.1.130	14:da:e9:cd:9f:0c	M-SEARCH Request	-
1668040683.884088	192.168.1.130	14:da:e9:cd:9f:0c	M-SEARCH Request	Google Chrome/106.0.5249.119 Linux
#close	2023-09-13-04-35-24
```

## 関連ソフトウエア

本プラグインは[OsecT](https://github.com/nttcom/OsecT)で利用されています。

