# Build-Your-Own-Ransomware: Hands-On Offensive and Defensive Insights

Slides:

[Part 1](./slides/BYOR.pdf)

## Exercises

### Time to Write Your Own Ransomware

- Implement hybrid encryption
  - Master + Ephemeral Keys
  - Encryption + Decryption
    - String - one program
    - File - one program
    - File - two program
- File System Enumeration
  - Depth or Breadth First Search
  - Print out the files you discover
  - Realize then you want to skip certain folders

### Applying Evasion

- Review the references and slides
  - Apply the techniques to your ransomware

Examples:

- Different encryption strategies
- File System Enumeration (not DFS/BFS)

## References

[ransom-osx](./ransom-osx/locker/main.go)

- macOS (Go)

[BYOR Demo](./byor/README.md)

- Different Encryption Algorithms
- Different File Discovery Strategies
- Different Encryption Strategies (partial/blocks/full)

[Conti Ransomware](https://github.com/gharty03/Conti-Ransomware)

- Windows (C++)
- Source Code Analysis Video: (https://youtu.be/SGbhqwXB-GU)

[Babuk Ransomware](hhttps://github.com/Hildaboo/BabukRansomwareSourceCode/tree/main)

- EXSI (Golang)
- Nas (C)
- Windows (C++)

[Windows Ransomware Detection](https://youtu.be/5t67BFcC-MQ)

- Slides: https://github.com/rad9800/talks/blob/main/windows-ransomware-detection.pdf

[RansomFS - Ransomware Detection](https://github.com/rad9800/RansomFS)

- Detecting Ransomware using the Projected File System

[BootExecute Ransomware](./bootexecute/README.md)
