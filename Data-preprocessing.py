import pandas as pd

user_response = input("Does the data need processing? (yes/no): ")

'''
 def process_table(file_path):
    try:
        df = pd.read_csv(file_path)

        if df.shape[1] < 1:
            print("The input file has no columns to process.")
            return

        first_col = df.columns[0]
        df[first_col] = pd.to_numeric(df[first_col], errors='coerce')

        condition = (df[first_col] >= 0) & (df[first_col] <= 1000)

        filtered_df = df[~condition].reset_index(drop=True)
        final_df = filtered_df.drop(columns=[first_col])
        final_df.to_csv(file_path, index=False)

        print(f"Processing complete. The output is saved to '{file_path}'.")

    except FileNotFoundError:
        print(f"The file '{file_path}' does not exist.")
    except pd.errors.EmptyDataError:
        print("The input file is empty.")
    except Exception as e:
        print(f"An error occurred: {e}")
'''

yes = {'yes', 'y', 'YES', 'Yes', 'yEs', 'yeS'}

no = {'tt'}

if user_response.lower() in no:
    file_path = 'Radiation Data/20241025_10_30_54.csv'
    data = pd.read_csv(file_path, header=None)

    data = data.iloc[:, 3:]

    data = data.iloc[3:]

    data.to_csv(file_path, index=False, header=False)

    print("First 4 columns and first 3 rows have been removed successfully.")
    # process_table(file_path)
    # data = pd.read_csv(file_path, header=None)
    # data = data.iloc[1:]
    # data.to_csv(file_path, index=False, header=False)
else:
    print("Ok")
