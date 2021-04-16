import pickle

data = pickle.load(open("analysis.pickle", "rb"))

max_classes = 0
total_classes = 0
packages_where_class = 0

print("Number of packages", len(data))

for package in data:
    classes = 0
    for file in package:
        classes += len(file)
        total_classes += len(file)
    max_classes = classes if classes > max_classes else max_classes
    if classes > 0:
        packages_where_class += 1

print("Max number of classes in a package", max_classes)
print("Total number of classes", total_classes)
print("Mean number of classes when there are classes", total_classes / packages_where_class)
