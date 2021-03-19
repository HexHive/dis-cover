#include<iostream>
using namespace std;

class A {
 public:
  int a;
  virtual void f1() {
    cout << "Af1()\n";
  }
  virtual void f2() {
    cout << "Af2()\n";
  }
};

class B : public A {
  public:
    int b;
  virtual void f1() {
    cout << "Bf1\n";
  }
};

int main(int argc, char *argv[]) {
  A *a;
  if (argc == 0) {
    a = new A();
  } else {
    a = new B();
  }
  a->f1();
  a->f2();
  a->f1();
  delete a;
}
