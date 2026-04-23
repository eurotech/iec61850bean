/*
 * Copyright 2011 The IEC61850bean Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.beanit.iec61850bean.app;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;

import com.beanit.iec61850bean.BasicDataAttribute;
import com.beanit.iec61850bean.BdaInt8;
import com.beanit.iec61850bean.BdaInt8U;
import com.beanit.iec61850bean.BdaOctetString;
import com.beanit.iec61850bean.BdaTimestamp;
import com.beanit.iec61850bean.BdaTriggerConditions;
import com.beanit.iec61850bean.Brcb;
import com.beanit.iec61850bean.ClientAssociation;
import com.beanit.iec61850bean.ClientEventListener;
import com.beanit.iec61850bean.ClientSap;
import com.beanit.iec61850bean.DataSet;
import com.beanit.iec61850bean.Fc;
import com.beanit.iec61850bean.FcModelNode;
import com.beanit.iec61850bean.ModelNode;
import com.beanit.iec61850bean.Report;
import com.beanit.iec61850bean.SclParseException;
import com.beanit.iec61850bean.SclParser;
import com.beanit.iec61850bean.ServerModel;
import com.beanit.iec61850bean.ServiceError;
import com.beanit.iec61850bean.Urcb;
import com.beanit.iec61850bean.internal.cli.Action;
import com.beanit.iec61850bean.internal.cli.ActionException;
import com.beanit.iec61850bean.internal.cli.ActionListener;
import com.beanit.iec61850bean.internal.cli.ActionProcessor;
import com.beanit.iec61850bean.internal.cli.CliParameter;
import com.beanit.iec61850bean.internal.cli.CliParameterBuilder;
import com.beanit.iec61850bean.internal.cli.CliParseException;
import com.beanit.iec61850bean.internal.cli.CliParser;
import com.beanit.iec61850bean.internal.cli.IntCliParameter;
import com.beanit.iec61850bean.internal.cli.StringCliParameter;
import com.beanit.iec61850bean.internal.mms.asn1.InformationReport;
import com.google.protobuf.EnumValue;

public class ConsoleClient {

  private static final String PRINT_MODEL_KEY = "m";
  private static final String PRINT_MODEL_KEY_DESCRIPTION = "print model";
  private static final String GET_DATA_VALUES_KEY = "g";
  private static final String GET_DATA_VALUES_KEY_DESCRIPTION = "send GetDataValues request";
  private static final String READ_ALL_DATA_KEY = "ga";
  private static final String READ_ALL_DATA_KEY_DESCRIPTION = "update all data in the model";
  private static final String CREATE_DATA_SET_KEY = "cds";
  private static final String CREATE_DATA_SET_KEY_DESCRIPTION = "create data set";
  private static final String DELETE_DATA_SET_KEY = "dds";
  private static final String DELETE_DATA_SET_KEY_DESCRIPTION = "delete data set";
  private static final String REPORTING_KEY = "r";
  private static final String REPORTING_KEY_DESCRIPTION = "configure reporting";
  private static final String COMMAND_KEY = "c";
  private static final String COMMAND_KEY_DESCRIPTION = "execute SBOw command";

  protected static final Pattern REFERENCE_DELIMITERS = Pattern.compile("[./]");

  private static final StringCliParameter hostParam = new CliParameterBuilder("-h")
      .setDescription("The IP/domain address of the server you want to access.").setMandatory()
      .buildStringParameter("host");
  private static final IntCliParameter portParam = new CliParameterBuilder("-p")
      .setDescription("The port to connect to.").buildIntParameter("port", 102);
  private static final StringCliParameter modelFileParam = new CliParameterBuilder("-m").setDescription(
      "The file name of the SCL file to read the model from. If this parameter is omitted the model will be read from the server device after connection.")
      .buildStringParameter("model-file");
  private static final StringCliParameter keystorePath = new CliParameterBuilder("-k")
      .setDescription("Path to a keystore file for enabling TLS").buildStringParameter("keystore-file");
  private static final StringCliParameter keystorePassword = new CliParameterBuilder("-kp")
      .setDescription("Keystore password").buildStringParameter("keystore-password");
  protected static final long TEST_SECONDS_FROM_EPOCH = 1773062849;

  private Optional<WriteValue<?>> writeValue = Optional.empty();

  private static final ActionProcessor actionProcessor = new ActionProcessor(new ActionExecutor());
  private static volatile ClientAssociation association;
  private static ServerModel serverModel;

  public static void main(String[] args) {

    List<CliParameter> cliParameters = new ArrayList<>();
    cliParameters.add(hostParam);
    cliParameters.add(portParam);
    cliParameters.add(modelFileParam);
    cliParameters.add(keystorePath);
    cliParameters.add(keystorePassword);

    CliParser cliParser = new CliParser("iec61850bean-console-client",
        "A client application to access IEC 61850 MMS servers.");
    cliParser.addParameters(cliParameters);

    try {
      cliParser.parseArguments(args);
    } catch (CliParseException e1) {
      System.err.println("Error parsing command line parameters: " + e1.getMessage());
      System.out.println(cliParser.getUsageString());
      System.exit(1);
    }

    InetAddress address;
    try {
      address = InetAddress.getByName(hostParam.getValue());
    } catch (UnknownHostException e) {
      System.out.println("Unknown host: " + hostParam.getValue());
      return;
    }

    ClientSap clientSap;

    if (keystorePath.isSelected()) {
      try {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream fis = new FileInputStream(keystorePath.getValue())) {
          char[] pwd = keystorePassword.isSelected() ? keystorePassword.getValue().toCharArray() : null;
          keyStore.load(fis, pwd);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        // use the keystore password for the key manager (may be null)
        char[] pwd = keystorePassword.isSelected() ? keystorePassword.getValue().toCharArray() : null;
        kmf.init(keyStore, pwd);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        clientSap = new ClientSap(sslContext.getSocketFactory());
      } catch (Exception e) {
        System.out.println("Unable to initialize TLS: " + e.getMessage());
        return;
      }
    } else {
      clientSap = new ClientSap();
    }

    try {
      association = clientSap.associate(address, portParam.getValue(), null, new EventListener());
    } catch (IOException e) {
      System.out.println("Unable to connect to remote host:" + e.getMessage());
      e.printStackTrace();
      return;
    }

    Runtime.getRuntime().addShutdownHook(new Thread() {

      @Override
      public void run() {
        association.close();
      }
    });

    System.out.println("successfully connected");

    if (modelFileParam.isSelected()) {
      System.out.println("reading model from file...");

      try {
        serverModel = SclParser.parse(modelFileParam.getValue()).get(0);
      } catch (SclParseException e1) {
        System.out.println("Error parsing SCL file: " + e1.getMessage());
        return;
      }

      association.setServerModel(serverModel);

      System.out.println("successfully read model");

    } else {
      System.out.println("retrieving model...");

      try {
        serverModel = association.retrieveModel();
      } catch (ServiceError e) {
        System.out.println("Service error: " + e.getMessage());
        return;
      } catch (IOException e) {
        System.out.println("Fatal error: " + e.getMessage());
        return;
      }

      System.out.println("successfully read model");
    }

    actionProcessor.addAction(new Action(PRINT_MODEL_KEY, PRINT_MODEL_KEY_DESCRIPTION));
    actionProcessor.addAction(new Action(GET_DATA_VALUES_KEY, GET_DATA_VALUES_KEY_DESCRIPTION));
    actionProcessor.addAction(new Action(READ_ALL_DATA_KEY, READ_ALL_DATA_KEY_DESCRIPTION));
    actionProcessor.addAction(new Action(CREATE_DATA_SET_KEY, CREATE_DATA_SET_KEY_DESCRIPTION));
    actionProcessor.addAction(new Action(DELETE_DATA_SET_KEY, DELETE_DATA_SET_KEY_DESCRIPTION));
    actionProcessor.addAction(new Action(REPORTING_KEY, REPORTING_KEY_DESCRIPTION));
    actionProcessor.addAction(new Action(COMMAND_KEY, COMMAND_KEY_DESCRIPTION));

    actionProcessor.start();
  }

  private static class EventListener implements ClientEventListener {

    @Override
    public void newReport(Report report) {
      System.out.println("\n----------------");
      System.out.println("Received report: ");
      System.err.println(report);
      System.out.println("------------------");
    }

    @Override
    public void associationClosed(IOException e) {
      System.out.print("Received connection closed signal. Reason: ");
      if (!e.getMessage().isEmpty()) {
        System.out.println(e.getMessage());
      } else {
        System.out.println("unknown");
      }
      actionProcessor.close();
    }

    @Override
    public void newRawReport(InformationReport report) {
      System.out.println("raw report: " + report);
    }
  }

  private static class ActionExecutor implements ActionListener {

    @Override
    public void actionCalled(String actionKey) throws ActionException {
      try {
        switch (actionKey) {
          case PRINT_MODEL_KEY:
            System.out.println(serverModel);
            break;
          case READ_ALL_DATA_KEY:
            System.out.print("Reading all data...");
            try {
              association.getAllDataValues();
            } catch (ServiceError e) {
              System.err.println("Service error: " + e.getMessage());
            }
            System.out.println("done");
            break;
          case GET_DATA_VALUES_KEY: {
            if (serverModel == null) {
              System.out.println("You have to retrieve the model before reading data.");
              return;
            }

            FcModelNode fcModelNode = askForFcModelNode();

            System.out.println("Sending GetDataValues request...");

            try {
              association.getDataValues(fcModelNode);
            } catch (ServiceError e) {
              System.out.println("Service error: " + e.getMessage());
              return;
            } catch (IOException e) {
              System.out.println("Fatal error: " + e.getMessage());
              return;
            }

            System.out.println("Successfully read data.");
            System.out.println(fcModelNode);

            break;
          }
          case CREATE_DATA_SET_KEY: {
            System.out.println("Enter the reference of the data set to create (e.g. myld/MYLN0.dataset1): ");
            String reference = actionProcessor.getReader().readLine();

            System.out.println("How many entries shall the data set have: ");
            String numberOfEntriesString = actionProcessor.getReader().readLine();
            int numDataSetEntries = Integer.parseInt(numberOfEntriesString);

            List<FcModelNode> dataSetMembers = new ArrayList<>();
            for (int i = 0; i < numDataSetEntries; i++) {
              dataSetMembers.add(askForFcModelNode());
            }

            DataSet dataSet = new DataSet(reference, dataSetMembers);
            System.out.print("Creating data set..");
            association.createDataSet(dataSet);
            System.out.println("done");

            break;
          }
          case DELETE_DATA_SET_KEY: {
            System.out.println("Enter the reference of the data set to delete (e.g. myld/MYLN0.dataset1): ");
            String reference = actionProcessor.getReader().readLine();

            DataSet dataSet = serverModel.getDataSet(reference);
            if (dataSet == null) {
              throw new ActionException("Unable to find data set with the given reference.");
            }
            System.out.print("Deleting data set..");
            association.deleteDataSet(dataSet);
            System.out.println("done");

            break;
          }
          case REPORTING_KEY: {
            System.out.println("Enter the URCB reference: ");
            String reference = actionProcessor.getReader().readLine();
            Urcb urcb = serverModel.getUrcb(reference);
            if (urcb == null) {
              Brcb brcb = serverModel.getBrcb(reference);
              if (brcb != null) {
                throw new ActionException(
                    "Though buffered reporting is supported by the library it is not yet supported by the console application.");
              }
              throw new ActionException("Unable to find RCB with the given reference.");
            }

            while (true) {
              association.getRcbValues(urcb);
              System.out.println();
              System.out.println(urcb);
              System.out.println();
              System.out.println("What do you want to configure?");
              System.out.println("1 - reserve");
              System.out.println("2 - cancel reservation");
              System.out.println("3 - enable");
              System.out.println("4 - disable");
              System.out.println("5 - set data set");
              System.out.println("6 - set trigger options");
              System.out.println("7 - set integrity period");
              System.out.println("8 - send general interrogation");
              System.out.println("0 - quit");
              try {
                int rcbAction = Integer.parseInt(actionProcessor.getReader().readLine());
                switch (rcbAction) {
                  case 0:
                    return;
                  case 1:
                    System.out.print("Reserving RCB..");
                    association.reserveUrcb(urcb);
                    System.out.println("done");
                    break;
                  case 2:
                    System.out.print("Canceling RCB reservation..");
                    association.cancelUrcbReservation(urcb);
                    System.out.println("done");
                    break;
                  case 3:
                    System.out.print("Enabling reporting..");
                    association.enableReporting(urcb);
                    System.out.println("done");
                    break;
                  case 4:
                    System.out.print("Disabling reporting..");
                    association.disableReporting(urcb);
                    System.out.println("done");
                    break;
                  case 5: {
                    System.out.print("Set data set reference:");
                    String dataSetReference = actionProcessor.getReader().readLine();
                    urcb.getDatSet().setValue(dataSetReference);
                    List<ServiceError> serviceErrors = association.setRcbValues(urcb, false, true, false, false, false,
                        false, false, false);
                    if (serviceErrors.get(0) != null) {
                      throw serviceErrors.get(0);
                    }
                    System.out.println("done");
                    break;
                  }
                  case 6: {
                    System.out
                        .print("Set the trigger options (data change, data update, quality change, interity, GI):");
                    String triggerOptionsString = actionProcessor.getReader().readLine();
                    String[] triggerOptionsStrings = triggerOptionsString.split(",", -1);
                    BdaTriggerConditions triggerOptions = urcb.getTrgOps();
                    triggerOptions.setDataChange(Boolean.parseBoolean(triggerOptionsStrings[0]));
                    triggerOptions.setDataUpdate(Boolean.parseBoolean(triggerOptionsStrings[1]));
                    triggerOptions.setQualityChange(Boolean.parseBoolean(triggerOptionsStrings[2]));
                    triggerOptions.setIntegrity(Boolean.parseBoolean(triggerOptionsStrings[3]));
                    triggerOptions.setGeneralInterrogation(Boolean.parseBoolean(triggerOptionsStrings[4]));
                    List<ServiceError> serviceErrors = association.setRcbValues(urcb, false, false, false, false, true,
                        false, false, false);
                    if (serviceErrors.get(0) != null) {
                      throw serviceErrors.get(0);
                    }
                    System.out.println("done");
                    break;
                  }
                  case 7: {
                    System.out.print("Specify integrity period in ms:");
                    String integrityPeriodString = actionProcessor.getReader().readLine();
                    urcb.getIntgPd().setValue(Long.parseLong(integrityPeriodString));
                    List<ServiceError> serviceErrors = association.setRcbValues(urcb, false, false, false, false, false,
                        true, false, false);
                    if (serviceErrors.get(0) != null) {
                      throw serviceErrors.get(0);
                    }
                    System.out.println("done");
                    break;
                  }
                  case 8:
                    System.out.print("Sending GI..");
                    association.startGi(urcb);
                    System.out.println("done");
                    break;
                  default:
                    System.err.println("Unknown option.");
                    break;
                }
              } catch (ServiceError e) {
                System.err.println("Service error: " + e.getMessage());
              } catch (NumberFormatException e) {
                System.err.println("Cannot parse number: " + e.getMessage());
              }
            }
          }
          case COMMAND_KEY: {
            if (serverModel == null) {
              System.out.println("You have to retrieve the model before issuing acommand.");
              return;
            }

            FcModelNode fcModelNode = askForFcModelNode();

            // Support only BdaInt8 for now
            byte ctlVal = askForCtlVal();
            try {
              final WriteValue<FcModelNode> selectWriteValue = new WriteValue<FcModelNode>(fcModelNode) //
                  .withAttribute("ctlVal", BdaInt8.class, BdaInt8::setValue, ctlVal) //
                  .withAttribute("ctlNum", BdaInt8U.class, BdaInt8U::setValue, (short) 1) //
                  .withAttribute("T", BdaTimestamp.class, BdaTimestamp::setInstant,
                      Instant.ofEpochSecond(TEST_SECONDS_FROM_EPOCH)) //
                  .withAttribute("origin.orCat", BdaInt8.class, BdaInt8::setValue, (byte) 8);

              select(selectWriteValue);

              String fcModelNodeName = fcModelNode.getReference().toString();
              Fc fc = fcModelNode.getFc();
              if (fcModelNodeName.endsWith(".SBOw")) {
                String fcModelNameOper = fcModelNodeName.substring(0, fcModelNodeName.lastIndexOf(".SBOw"));
                FcModelNode fcModelNodeOper = retrieveFcModelNode(fcModelNameOper, fc);
                final WriteValue<FcModelNode> operateWriteValue = new WriteValue<FcModelNode>(fcModelNodeOper) //
                    .withAttribute("Oper.ctlVal", BdaInt8.class, BdaInt8::setValue, ctlVal) //
                    .withAttribute("Oper.T", BdaTimestamp.class, BdaTimestamp::setInstant,
                        Instant.ofEpochSecond(TEST_SECONDS_FROM_EPOCH)) //
                    .withAttribute("Oper.ctlNum", BdaInt8U.class, BdaInt8U::setValue, (short) 1) //
                    .withAttribute("Oper.origin.orCat", BdaInt8.class, BdaInt8::setValue, (byte) 8);

                operate(operateWriteValue);
              } else {
                System.out.println(
                    "Warning: The reference you entered does not end with .SBOw. The library will only send a Select (not Operate) command. If you want to send an Operate command, please enter the reference of the SBOw node (e.g. myld/MYLN0.do.SBOw instead of myld/MYLN0.do).");
              }

            } catch (ServiceError e) {
              System.out.println("Service error: " + e.getMessage());
              return;
            } catch (IOException e) {
              System.out.println("Fatal error: " + e.getMessage());
              return;
            }
            System.out.println("Successfully sent command.");
            break;
          }
          default:
            break;
        }
      } catch (Exception e) {
        System.out.println("Error executing action: " + e.getMessage());
      }
    }

    //

    private byte askForCtlVal() throws IOException {
      System.out.println("Enter the ctlVal to send: ");
      String ctlValString = actionProcessor.getReader().readLine();
      byte ctlVal;
      try {
        ctlVal = Byte.parseByte(ctlValString);
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Invalid ctlVal: " + ctlValString);
      }
      return ctlVal;
    }

    protected void select(WriteValue<?> writeValue) throws ServiceError, IOException {
      writeValue.write();
    }

    protected void operate(WriteValue<?> writeValue) throws ServiceError, IOException {
      association.operate(writeValue.attribute);
    }

    protected class WriteValue<T extends FcModelNode> {

      private final T attribute;

      private WriteValue(final T attr) {
        this.attribute = attr;
      }

      public <U> WriteValue<T> withField(final BiConsumer<T, U> setter, final U value) {
        setter.accept(this.attribute, value);
        return this;
      }

      public <U extends BasicDataAttribute, V> WriteValue<T> withAttribute(final String path, final Class<U> ty,
          final BiConsumer<U, V> setter, final V value) {
        final ModelNode node = lookup(this.attribute, path)
            .orElseThrow(() -> new IllegalStateException("node at path " + path + " not found"));
        new WriteValue<>(ty.cast(node)).withField(setter, value);
        return this;
      }

      public void write() throws ServiceError, IOException {
        association.setDataValues(this.attribute);
      }
    }

    protected FcModelNode retrieveFcModelNode(final String reference, final Fc fc) {

      final FcModelNode asFcModelNode = retrieveNode(reference, FcModelNode.class, fc);

      try {
        association.getDataValues(asFcModelNode);
      } catch (Exception e) {
        fail("cannot read value from " + reference + ' ' + e);
      }

      return asFcModelNode;
    }

    protected <T> T retrieveNode(final String reference, final Class<T> clazz, final Fc fc) {
      final Optional<ModelNode> node = retrieveNode(reference, fc);

      return node.filter(clazz::isInstance).map(clazz::cast).orElseThrow(() -> new IllegalStateException(
          "node " + reference + ' ' + node + " is not a " + clazz.getSimpleName()));
    }

    protected Optional<ModelNode> retrieveNode(final String reference, final Fc fc) {
      return Optional.ofNullable(serverModel.findModelNode(reference, fc));
    }

    protected Optional<ModelNode> lookup(final ModelNode parent, final String path) {
      final Iterator<String> iter = splitRefernce(path);

      Optional<ModelNode> node = Optional.ofNullable(parent);

      while (iter.hasNext() && node.isPresent()) {
        final String next = iter.next();

        final Optional<ModelNode> nextNode = Optional.ofNullable(node.get().getChild(next));

        if (!nextNode.isPresent()) {
          System.out.println("node not found: current: " + node + ", next: " + next);
          return Optional.empty();
        }

        node = nextNode;
      }

      return node;
    }

    protected static Iterator<String> splitRefernce(final String ref) {
      return REFERENCE_DELIMITERS.splitAsStream(ref).iterator();
    }

    //
    private FcModelNode askForFcModelNode() throws IOException, ActionException {
      System.out.println("Enter reference (e.g. myld/MYLN0.do.da.bda): ");
      String reference = actionProcessor.getReader().readLine();
      System.out.println("Enter functional constraint of referenced node: ");
      String fcString = actionProcessor.getReader().readLine();

      Fc fc = Fc.fromString(fcString);
      if (fc == null) {
        throw new ActionException("Unknown functional constraint.");
      }

      return getFcModelNode(reference, fc);
    }

    FcModelNode getFcModelNode(String reference, Fc fc) throws ActionException {
      ModelNode modelNode = serverModel.findModelNode(reference, fc);
      if (modelNode == null) {
        throw new ActionException(
            "A model node with the given reference and functional constraint could not be found.");
      }

      if (!(modelNode instanceof FcModelNode)) {
        throw new ActionException("The given model node is not a functionally constraint model node.");
      }

      return (FcModelNode) modelNode;
    }

    @Override
    public void quit() {
      System.out.println("** Closing connection.");
      association.close();
      return;
    }
  }
}
