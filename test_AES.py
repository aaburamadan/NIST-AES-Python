import time
import numpy as np
from AES_padded import run_aes_encryption, run_aes_decryption
import pandas as pd
import matplotlib.pyplot as plt
import os
from tqdm import tqdm


def test_aes_performance():
    """
        Tests AES encryption and decryption performance across different key sizes and modes.
        Generates performance plots and saves them to the 'plots' directory.
    """
    # input_string = "This is a test string for AES encryption performance measurement."
    # test long string
    input_string = "This is a test string for AES encryption performance measurement." * 5 # Repeat to increase size
    key_sizes = [128, 192, 256]
    modes = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
    num_runs = 50  # Number of runs for averaging

    # List to hold the performance data
    performance_data = []

    # Total number of iterations for the outer loops
    total_iterations = len(key_sizes) * len(modes) * num_runs

    # Iterate over key sizes and modes

    with tqdm(total=total_iterations, desc="Total Progress", unit="combination") as pbar:
        for key_size in key_sizes:
            for mode in modes:
                total_encrypt_time = 0
                total_decrypt_time = 0

                # Progress bar for the inner loop
                # Update the progress bar description for the current combination
                pbar.set_description(f"{key_size}-bit {mode}")
                for _ in range(num_runs):
                    # Encryption
                    start_encrypt = time.perf_counter()
                    ciphertext, key, iv, n_k, n_r, mode_used = run_aes_encryption(input_string, key_size, mode)
                    end_encrypt = time.perf_counter()
                    encryption_time = end_encrypt - start_encrypt
                    total_encrypt_time += encryption_time

                    # Decryption
                    start_decrypt = time.perf_counter()
                    decrypted_text = run_aes_decryption(ciphertext, key, iv, n_k, n_r, mode_used)
                    end_decrypt = time.perf_counter()
                    decryption_time = end_decrypt - start_decrypt
                    total_decrypt_time += decryption_time

                    # Verify correctness
                    try:
                        assert decrypted_text == input_string, "Decryption failed: Decrypted text does not match input."
                    except AssertionError as e:
                        print(e)
                        continue  # Skip to the next iteration

                    # Update progress bar
                    pbar.update(1)

                # Calculate average times
                avg_encrypt_time = total_encrypt_time / num_runs
                avg_decrypt_time = total_decrypt_time / num_runs

                # Append to performance data
                performance_data.append({
                    'Key Size (bits)': key_size,
                    'Mode': mode,
                    'Avg Encryption Time (ms)': avg_encrypt_time * 1000,  # Convert to milliseconds
                    'Avg Decryption Time (ms)': avg_decrypt_time * 1000   # Convert to milliseconds
                })

                pbar.update(1)  # Update the outer progress bar

    # Create a DataFrame for better visualization
    df_performance = pd.DataFrame(performance_data)

    # Print the DataFrame
    print(df_performance)

    # Plotting the results
    plot_performance(df_performance)
    plot_performance_single(df_performance)


def plot_performance(df):

    # Set the style of the plots
    plt.style.use('seaborn-v0_8-darkgrid')

    # Define the subfolder where you want to save the plots
    output_dir = 'plots'

    # Create the subfolder if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    key_sizes = df['Key Size (bits)'].unique()

    for key_size in key_sizes:
        df_key = df[df['Key Size (bits)'] == key_size]
        if df_key.empty:
            continue

        # Plot for Encryption Times
        plt.figure(figsize=(10, 6))
        plt.bar(df_key['Mode'], df_key['Avg Encryption Time (ms)'], color='skyblue')
        plt.title(f'AES Encryption Time for Key Size {key_size} bits')
        plt.xlabel('Mode')
        plt.ylabel('Average Encryption Time (ms)')
        plt.tight_layout()
        output_file = os.path.join(output_dir, f'encryption_time_{key_size}bits.png')
        plt.savefig(output_file)
        plt.close()  # Close the figure to free memory
        # plt.show()

        # Plot for Decryption Times
        plt.figure(figsize=(10, 6))
        plt.bar(df_key['Mode'], df_key['Avg Decryption Time (ms)'], color='salmon')
        plt.title(f'AES Decryption Time for Key Size {key_size} bits')
        plt.xlabel('Mode')
        plt.ylabel('Average Decryption Time (ms)')
        plt.tight_layout()
        output_file = os.path.join(output_dir, f'decryption_time_{key_size}bits.png')
        plt.savefig(output_file)
        plt.close()  # Close the figure to free memory
        # plt.show()

    # Plot combined Encryption and Decryption Times
    for key_size in key_sizes:
        df_key = df[df['Key Size (bits)'] == key_size]
        if df_key.empty:
            continue

        x = np.arange(len(df_key['Mode']))  # the label locations
        width = 0.35  # the width of the bars

        fig, ax = plt.subplots(figsize=(10, 6))
        rects1 = ax.bar(x - width/2, df_key['Avg Encryption Time (ms)'], width, label='Encryption')
        rects2 = ax.bar(x + width/2, df_key['Avg Decryption Time (ms)'], width, label='Decryption')

        # Add some text for labels, title and custom x-axis tick labels, etc.
        ax.set_ylabel('Time (ms)')
        ax.set_title(f'AES Performance for Key Size {key_size} bits')
        ax.set_xticks(x)
        ax.set_xticklabels(df_key['Mode'])
        ax.grid(True)
        ax.legend()

        fig.tight_layout()
        output_file = os.path.join(output_dir, f'performance_{key_size}bits.png')
        plt.savefig(output_file)
        # plt.show()
        plt.close()


def plot_performance_single(df):

    # Use a style
    plt.style.use('seaborn-v0_8-darkgrid')  # Adjust based on available styles

    # Define the subfolder where you want to save the plots
    output_dir = 'plots'

    # Create the subfolder if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create a figure and axis
    fig, ax = plt.subplots(figsize=(12, 8))

    # Get the list of modes and key sizes
    modes = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
    key_sizes = df['Key Size (bits)'].unique()

    # Plot average encryption times
    for key_size in sorted(key_sizes):
        df_key = df[df['Key Size (bits)'] == key_size]
        if df_key.empty:
            continue

        # Ensure the modes are in the correct order
        df_key = df_key.set_index('Mode').reindex(modes).reset_index()
        ax.plot(df_key['Mode'], df_key['Avg Encryption Time (ms)'],
                marker='o', label=f'Encryption - {key_size}-bit Key')

    # Plot average decryption times
    for key_size in sorted(key_sizes):
        df_key = df[df['Key Size (bits)'] == key_size]
        if df_key.empty:
            continue

        # Ensure the modes are in the correct order
        df_key = df_key.set_index('Mode').reindex(modes).reset_index()
        ax.plot(df_key['Mode'], df_key['Avg Decryption Time (ms)'],
                marker='x', linestyle='--', label=f'Decryption - {key_size}-bit Key')

    # Set labels and title
    ax.set_xlabel('AES Mode')
    ax.set_ylabel('Average Time (ms)')
    ax.set_title('AES Encryption and Decryption Performance Across Modes and Key Sizes')

    # Add legend
    ax.legend()

    # Adjust layout and show plot
    plt.tight_layout()
    output_file = os.path.join(output_dir, f'aes_performance_comparison.png')
    plt.savefig(output_file)
    #plt.show()
    plt.close()


if __name__ == "__main__":
    test_aes_performance()
