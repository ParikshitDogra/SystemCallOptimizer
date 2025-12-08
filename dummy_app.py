import time
import os
import random

def perform_file_io():
    """Generates open, write, read, close syscalls."""
    filename = "test_data.txt"
    with open(filename, "w") as f:
        f.write("Logging some data to the disk...\n" * 10)
    
    with open(filename, "r") as f:
        _ = f.read()
    
    os.remove(filename)

def perform_sleep():
    """Generates nanosleep/select syscalls."""
    duration = random.uniform(0.1, 0.5)
    time.sleep(duration)

def perform_computation():
    """Generates mostly user-space activity, but some brk/mmap potentially."""
    _ = [x**2 for x in range(10000)]

def main():
    print(f"Dummy App Started with PID: {os.getpid()}")
    print("Generating system calls... (Press Ctrl+C to stop manually)")
    
    try:
        while True:
            action = random.choice([perform_file_io, perform_sleep, perform_computation])
            action()
            # print(f"Performed {action.__name__}") # Uncomment to see activity
    except KeyboardInterrupt:
        print("\nDummy App Stopping.")

if __name__ == "__main__":
    main()