## これは何
Rustで作成したファイルを暗号化するプログラムです

⚠️専門的な検査を受けていないため、安全性につては保証出来ません

## 仕様方法
### 暗号化する
`-e`で暗号化することを示します

`<target file>.enc`の形式で保存されます。
```
cargo run --release -- -e <target file>
```

保存されるファイル名を指定するには`-o <file name>`オプションを仕様します
```
cargo run --release -- -e <target file> -o <out file>
```

### 復号化する
`-d`で復号化することを示します

暗号化される前のファイル名で保存されます

```
cargo run --release -- -d <target file>
```

保存されるファイル名を指定するには`-o <file name>`オプションを仕様します
```
cargo run --release -- -d <target file> -o <out file>
```
