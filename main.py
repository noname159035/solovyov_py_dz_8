import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

df = pd.read_json("events.json")

print("Размер таблицы:", df.shape)
print(df.head())

# 2) Анализ распределения по signature
signature_counts = df["signature"].value_counts().reset_index()
signature_counts.columns = ["signature", "count"]

print("\nРаспределение по signature:")
print(signature_counts)

# 3) Визуализация
sns.set_theme()

plt.figure(figsize=(12, 6))
sns.barplot(data=signature_counts, x="signature", y="count")
plt.title("Распределение событий по signature")
plt.xlabel("Тип события (signature)")
plt.ylabel("Количество")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.show()
