from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "dataset" / "raw"

csv_files = sorted(RAW.glob("*.csv"))

print(f"\nFOUND {len(csv_files)} CSV FILES\n")

for path in csv_files:

    print("=" * 90)
    print("FILE:", path.name)
    print(f"SIZE: {path.stat().st_size / (1024 ** 2):.2f} MB")
    print("=" * 90)

    try:
        # Read only a few rows first — prevents huge memory usage
        sample = pd.read_csv(path, nrows=5, low_memory=False)

        print("\nNumber of columns:", len(sample.columns))

        print("\nFirst 10 columns:")
        print(list(sample.columns[:10]))

        print("\nLast 10 columns:")
        print(list(sample.columns[-10:]))

        print("\nSample:")
        print(sample.head())

        # Check for likely label
        label_found = None

        for label in [
            "Class",
            "class",
            "Label",
            "label",
            "Category",
            "category"
        ]:
            if label in sample.columns:
                label_found = label
                break

        if label_found:
            print("\nPossible label column:", label_found)
        else:
            print("\nNo obvious label column found.")

        print("\nStatus: ✓ Successfully inspected")

    except Exception as e:

        print("\n❌ Could not inspect this file.")
        print("Error:", type(e).__name__)
        print("Message:", e)

    print()