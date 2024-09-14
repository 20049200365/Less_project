# Dataset

Enron : https://www.cs.cmu.edu/~enron/

World Language: https://www.statmt.org/lm-benchmark/

# Run code

1. Change datasize and keyword_size

   ​	datasize：the number of file

   ​	keyword_size is the number of keywords contained in each file. By default, the number of keywords in each file is the same.

2. Change file path cipher_path,key_path,key_original_path and data_path.

   ​	The file represented by cipher_path,key_path,key_original_path is generated in code.

   ​	The file represented by data_path is experimental data, which must exist before code generation.
   
4. We also present a scheme 'Less_free.java' with less storage overhead. Although its query speed is slightly reduced, it is still much faster than Dory.

# Result

Take the query {"travel", "busi", "meet", "fun", "trip", "especi"} in Enron dataset as an example

```java
[travel, busi, meet, fun, trip, especi]
num of search_word:6
Build time:203122.3022ms
store_cost_recording:3178043472 byte
Client - search query generation time:8.9305ms
Queries cost:61424 byte
Server search time:237.66ms
Server returns cost:4185048 byte
Mac verification succeeded!
No.1 No.282 No.887 No.2385 No.2669 No.264782 
Client query time:2112.1799ms
```

