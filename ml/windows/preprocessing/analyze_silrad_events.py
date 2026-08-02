from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[3]

DATASET_DIR = ROOT / "dataset" / "windows" / "raw"

FILES = [
    "fasttext-all-nofamily.csv",
    "fasttext-trainmodel.csv",
    "fasttext-testmodel.csv",
]

for filename in FILES:

    path = DATASET_DIR / filename

    print("\n" + "=" * 80)
    print(filename)
    print("=" * 80)

    # We only need two columns, so this is memory efficient
    df = pd.read_csv(
        path,
        usecols=["event.code", "class"]
    )

    print(f"\nRows: {len(df):,}")

    print("\nCLASS DISTRIBUTION")
    print("-" * 50)

    print(
        df["class"]
        .value_counts()
        .sort_index()
    )

    print("\nEVENT ID DISTRIBUTION")
    print("-" * 50)

    print(
        df["event.code"]
        .value_counts()
        .sort_index()
    )

    print("\nEVENT IDs BY CLASS")
    print("-" * 50)

    table = pd.crosstab(
        df["event.code"],
        df["class"]
    )

    print(table)

    print("\nUnique Event IDs:")

    event_ids = sorted(
        df["event.code"]
        .dropna()
        .unique()
    )

    print(event_ids)

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)