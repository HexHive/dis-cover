class A {
public:
  virtual void f() {}
};

class B : public A {
public:
  virtual void f() {}
};

int main(int argc, char *argv[]) {
  A *a_or_b;

  if (argc == 0) {
    a_or_b = new A();
  } else {
    a_or_b = new B();
  }

  a_or_b->f();

  delete a_or_b;
}
