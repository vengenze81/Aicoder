#!/usr/bin/env python3
"""
Print the first 10 Fibonacci numbers.
"""

def fibonacci_sequence(n: int):
    """Return a list containing the first n Fibonacci numbers."""
    if n <= 0:
        return []

    # The sequence starts with 0 and 1
    seq = [0]
    if n == 1:
        return seq

    seq.append(1)
    while len(seq) < n:
        # Next number is the sum of the last two
        seq.append(seq[-1] + seq[-2])
    return seq

def main():
    first_10 = fibonacci_sequence(10)
    for num in first_10:
        print(num)

if __name__ == "__main__":
    main()