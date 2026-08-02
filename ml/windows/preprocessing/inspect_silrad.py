from pathlib import Path
import pandas as pd


ROOT = Path(__file__).resolve().parents[3]

DATASET_DIR = ROOT / "dataset" / "windows" / "raw"

FILES = [
    "fasttext-all-nofamily.csv",
    "fasttext-trainmodel.csv",
    "fasttext-testmodel.csv",
]


print("=" * 80)
print("MALGUARD - SILRAD DATASET INSPECTION")
print("=" * 80)

print(f"\nDataset directory:\n{DATASET_DIR}")


for filename in FILES:

    path = DATASET_DIR / filename

    print("\n" + "=" * 80)
    print(f"FILE: {filename}")
    print("=" * 80)

    if not path.exists():
        print(f"ERROR: File not found:\n{path}")
        continue

    print(f"\nFile size: {path.stat().st_size / (1024 * 1024):.2f} MB")

    try:
        # Read header first
        header = pd.read_csv(path, nrows=0)

        print(f"\nNumber of columns: {len(header.columns)}")

        print("\nCOLUMN NAMES")
        print("-" * 80)

        for i, column in enumerate(header.columns):
            print(f"{i:3} -> {column}")

        # Read only a sample so large files don't consume unnecessary RAM
        df = pd.read_csv(path, nrows=20)

        print("\n" + "-" * 80)
        print("FIRST 5 ROWS")
        print("-" * 80)

        print(df.head().to_string())

        print("\n" + "-" * 80)
        print("DATA TYPES")
        print("-" * 80)

        print(df.dtypes)

        print("\n" + "-" * 80)
        print("POSSIBLE LABEL COLUMNS")
        print("-" * 80)

        candidates = [
            "label",
            "Label",
            "LABEL",
            "class",
            "Class",
            "CLASS",
            "family",
            "Family",
            "malware",
            "Malware",
            "type",
            "Type",
            "category",
            "Category",
        ]

        found = False

        for column in candidates:

            if column in df.columns:

                found = True

                print(f"\nPossible target: {column}")

                print(
                    df[column]
                    .value_counts(dropna=False)
                    .to_string()
                )

        if not found:
            print("No obvious label column detected.")

        print("\n" + "-" * 80)
        print("SYSMON-RELATED COLUMN SEARCH")
        print("-" * 80)

        keywords = [
            "event",
            "process",
            "image",
            "command",
            "network",
            "destination",
            "source",
            "file",
            "registry",
            "dns",
            "query",
            "parent",
        ]

        matching_columns = []

        for column in df.columns:

            lower = str(column).lower()

            if any(keyword in lower for keyword in keywords):
                matching_columns.append(column)

        if matching_columns:

            for column in matching_columns:
                print(column)

        else:
            print("No obvious Sysmon-related columns found.")

        print("\nStatus: Successfully inspected")

    except Exception as e:

        print("\nERROR while inspecting file:")
        print(type(e).__name__, "-", e)


print("\n" + "=" * 80)
print("INSPECTION COMPLETE")
print("=" * 80)