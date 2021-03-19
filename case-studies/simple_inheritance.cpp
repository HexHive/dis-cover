class A {
 public:
  int a;
  virtual void af1() {
    a = 23;
  }
  virtual void af2() {
    a = 42;
  }
};

class B : public A {
  public:
    int b;
};

int main() {
  B *b1;
  b1 = new B();
  B *b2;
  b2 = new B();
  b1->af1();
  b1->af2();
  b2->af2();
  delete b1;
  delete b2;
}
