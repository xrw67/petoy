# PE Toy

## 程序目录

| 名称            | 用途              |
|----------------|-------------------|
| common.h       | 一些工具函数        |
| main.cpp       | main函数           |
| packer.{h,cpp} | 处理加壳的主要代码   |
| shell.h        | 外壳的数据接口的定义  |
| shell.asm      | 外壳的代码(MASM汇编) |
| masm32         | MASM编译器          |




## 外壳部分的布局


| .petoy段   |
|------------|
| EOP        |
| 壳的输入表  |
| 壳的代码部分 |
| 壳的数据部分 |


elemeta <elemeta47 at gmail dot com>