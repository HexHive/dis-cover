class Storable {
public:
  virtual ~Storable() {}
  virtual void read() {}
};

class Transmitter : public Storable {
public:
  virtual void read() {}
};

class Receiver : public Storable {
public:
  virtual void read() {}
};

class Radio : public Transmitter, public Receiver {
public:
  virtual void read() {}
};

int main(int argc, char *argv[]) {

  Receiver *receiver;
  Transmitter *transmitter;

  if (argc == 0) {
    receiver = new Radio();
    transmitter = new Transmitter();
  } else {
    receiver = new Receiver();
    transmitter = new Radio();
  }

  receiver->read();
  transmitter->read();

  delete receiver;
  delete transmitter;
}
