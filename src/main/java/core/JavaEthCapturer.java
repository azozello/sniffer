package core;

import java.awt.Color;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class JavaEthCapturer {

    // Will be filled with NICs
    List alldevs = new ArrayList();
    // For any error msgs
    StringBuilder errbuf = new StringBuilder();
    //Getting a list of devices
    int r = Pcap.findAllDevs(alldevs, errbuf);
    int adp;
    int nbpct;
    boolean pc = false;
    String [] nbAdapterStrings = {"0", "1"};
    String [] nbAdpStrings = {"0", "1"};
    int bufrdCount;
    // Capture all packets, no trucation
    int snaplen = 64 * 1024;
    // capture all packets
    int flags = Pcap.MODE_PROMISCUOUS;
    // Timeout mc
//    static int timeout = 10000;
    int timeout = 100;

    private JButton stop = new JButton("Stop");
    private JButton start = new JButton("Start");
    private static  JTextArea input = new JTextArea("input");
    private JScrollPane scrollPaneInput = new JScrollPane(input);
    private JLabel label1 = new JLabel("Select an adapter");
    private JLabel label2 = new JLabel("Test1");
    private JLabel label3 = new JLabel("Test2");
    private JComboBox adapterList = new JComboBox();
    static private Pcap pcap = new Pcap();


    public class Form extends JFrame{

        String dv = "";

        public Form() {

            System.out.println(r);
            System.out.println(r);
            if (r != Pcap.OK) {
                System.err.printf("Can't read list of devices, error is %s", errbuf
                        .toString());
                return;
            }

            System.out.println("Network devices found:");
            int i = 0;
            for (Iterator it = alldevs.iterator(); it.hasNext();) {
                PcapIf device = (PcapIf) it.next();
                String description =
                        (device.getDescription() != null) ? device.getDescription()
                                : "No description available";
                // записать название адаптера в строку
                nbAdapterStrings[i] = description + "\n";
                nbAdpStrings[i] = description;
                dv = dv + nbAdapterStrings[i];
                // список адаптеров в adapterList
                adapterList.addItem(nbAdapterStrings[i]);
                i++;
            }
            input.setText(dv);
            initComponents();
        }

        private void initComponents(){
            setBounds(15,30,800,600);
            setSize(830, 600);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            Container container = getContentPane();
            container.setLayout(null);
            container.setBounds(5,5,800,600);

//----------------------------------------------------------------------
// JTextArea

            input.setLineWrap(true);
            input.setColumns(20);
            input.setRows(5);
            input.setBounds(10,220,790,300);
            container.add(input);
            // Добавление скрола
            scrollPaneInput.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
            scrollPaneInput.setBounds(10,220,800,300);
            container.add(scrollPaneInput);
            scrollPaneInput.setViewportView(input);

//----------------------------------------------------------------------
// JComboBox

            adapterList.setBounds(10,25,300,20);
            // зарегистрировать экземпляр класса обработчика события
            adapterList.addActionListener(new ethListEventListener());
            adapterList.setEnabled(true);
            container.add(adapterList);

//----------------------------------------------------------------------
// JLabel

            label1.setBounds(10,5,300,20);
            label1.setOpaque(true);
            label1.setForeground(Color.red);
            container.add(label1);
            //
            label2.setBounds(10,190,300,20);
            label2.setText("Lenght of packet");
            container.add(label2);
            //
            label3.setBounds(20,530,250,20);
            label3.setText("Frame number");
            container.add(label3);

//----------------------------------------------------------------------
// JButton

            start.addActionListener(new startEventListener());
            start.setBounds(440,155,80,25);
            start.setEnabled(false);
            container.add(start);

            stop.addActionListener(new stopEventListener());
            stop.setBounds(730,155,80,25);
            stop.setEnabled(false);
            container.add(stop);
        }

        class startEventListener implements ActionListener {

            public void actionPerformed(ActionEvent e) {
                // дезактивировать выбор адаптеров
                adapterList.setEnabled(false);
                // Флаг открытия pcap
                pc = true;
                stop.setEnabled(true);
            }
        }

        class stopEventListener implements ActionListener {
            public void actionPerformed(ActionEvent e) {
                pc = false;
                System.out.println(adp + " device close");
                label1.setOpaque(true);
                label1.setForeground(Color.red);
                label1.setText("Select an adapter");
                //Close the pcap
                pcap.close();
                start.setEnabled(false);
                adapterList.setEnabled(true);
                stop.setEnabled(false);
            }
        }

        class ethListEventListener implements ActionListener {

            String op = "Opened";

            public void actionPerformed(ActionEvent e) {
                // comName - выбранная строка в JComboBox comList
                JComboBox cb = (JComboBox)e.getSource();
                // получить номер выбранного адаптера
                adp = cb.getSelectedIndex();
                // выбор адаптера
                PcapIf device = (PcapIf) alldevs.get(adp);
                // отрыть выбранный адаптер
                pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
                if (pcap == null) {
                    input.setText("Error while opening device for capture: "
                            + errbuf.toString());
                }
                // выбранный адаптер в окне input
                input.setText(nbAdpStrings[adp] + "   " + op);
                // прозрачность label1 с послед. уст. цвета
                label1.setOpaque(true);
                label1.setForeground(Color.MAGENTA);
                label1.setText(nbAdapterStrings[adp]);
                start.setEnabled(true);
            }
        }
    }

//----------------------------------------------------------------------
// Хендлер метод

    PcapPacketHandler jpacketHandler = new PcapPacketHandler() {

        // строка данных
        String readData;
        // буфер данных
        byte[] bufrd = new byte [2000];

        public void nextPacket(PcapPacket packet, Object o) {
            byte[] data = packet.getByteArray(0, packet.size());
            // номер фрейма
            nbpct = (int) packet.getFrameNumber();
            input.setText("");
            readData = "";
            // количество байт фрейма
            label2.setText(String.format("Lenght of packet %d bytes", data.length));
            label3.setText(String.format("Frame number %d ", packet.getFrameNumber()));
            // перенос данных фрейма в форматированную строку
            for (int i = 0; i < data.length; i++){
                bufrd[i] = data[i];
                readData = readData + String.format("%02X ", bufrd[i]);
            }
            // данные фрейма в окно input
            input.setText(readData);
        }
    };

    // Поток с pcap.loop
    public class PcapLoopThread extends Thread {

        // переопределение метода run
        @Override
        public void run() {
            while(true)
            {
                try{
                    //Приостанавливает поток 1мс
                    sleep(1);
                    if(pc) {
                        // отлов одного пакета если был Start
                        pcap.loop(1, jpacketHandler, "jnetpcap rocks!");
                    }
                }catch(InterruptedException e){}
            }
        }
    }

    //----------------------------------------------------------------------
// Main
    public static void main(String[] args) {
        // создание объектов
        JavaEthCapturer javaEthTest = new JavaEthCapturer();
        JavaEthCapturer.Form form = javaEthTest.new Form();
        JavaEthCapturer.PcapLoopThread pcapLoopThread = javaEthTest.new PcapLoopThread();
        // по зарытию формы
        form.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // Запуск формы
        form.setVisible(true);
        // Запуск потока
        pcapLoopThread.start();
    }
}
