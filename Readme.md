# Dataset

Enron : https://www.cs.cmu.edu/~enron/

World Language: https://www.statmt.org/lm-benchmark/

# Run code

1. Change datasize and keyword_size

   ​	datasize：the number of file

   ​	keyword_size is the number of keywords contained in each file. By default, the number of keywords in each file is the same

2. Change file path cipher_path,key_path,key_original_path and data_path

   ​	The file represented by cipher_path,key_path,key_original_path is generated in code

   ​	The file represented by data_path is experimental data, which must exist before code generation

# Result

Take the query {"view", "last", "library", "penthouse"} in Enron.csv as an example

```java
[view, last, library, penthouse]
num of search_word:4 
Build time:252859.4145ms
store_cost_recording:3404255832
Queries cost:10592 byte
Server search time:1786.1044ms
Server returns cost:2419080 byte
Server returns cost:2418080 byte
No.0 
Client query time:1267.015ms
```

